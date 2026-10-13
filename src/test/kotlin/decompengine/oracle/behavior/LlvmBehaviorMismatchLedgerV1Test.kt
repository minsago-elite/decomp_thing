package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleArtifactException
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorMismatchLedgerV1Test {
    @Test
    fun `published ledger reloads exact immutable bytes without release or scoring authority`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("published")
        val annotation = accepted(assessment, "Reviewed difference in fixture exit status")

        val published = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, annotations = listOf(annotation))
        val path = directory.resolve("ledger-0001.json")
        val reloaded = LlvmBehaviorMismatchLedgerV1Store.verify(path, published.ledgerSha256)

        assertTrue(Files.isRegularFile(path))
        assertContentEquals(published.canonicalBytes, Files.readAllBytes(path))
        assertContentEquals(published.canonicalBytes, reloaded.canonicalBytes)
        assertEquals(OracleArtifacts.sha256(published.canonicalBytes), published.ledgerSha256)
        assertEquals(published.ledgerSha256, reloaded.ledgerSha256)
        assertEquals(1, reloaded.eventCount)
        assertEquals(1, reloaded.mismatchOccurrences)
        assertEquals(1, reloaded.acceptedAnnotationCount)
        assertEquals(0, reloaded.unresolvedAnnotationCount)
        assertFalse(reloaded.releaseEligible)
        assertFalse(reloaded.scoringAuthority)
        assertEquals("integrity-only-retained-comparison-and-annotations-v1", reloaded.authority)
        val document = ledgerDocument(reloaded)
        OracleSchemas.validate("llvm-behavior-mismatch-ledger-v1", document)
        assertEquals("untrusted-metadata-only", document.string("annotationAuthority"))
        assertContentEquals(assessment.canonicalBytes, retainedAssessment(document.events().single()))
        assertEquals(
            assessmentDocument(assessment).objectValue("summary"),
            retainedAssessmentDocument(document.events().single()).objectValue("summary"),
        )

        val exposedBytes = reloaded.canonicalBytes
        exposedBytes.fill(0)
        assertContentEquals(published.canonicalBytes, reloaded.canonicalBytes)
        assertContentEquals(published.canonicalBytes, Files.readAllBytes(path))
    }

    @Test
    fun `missing annotations preserve each mismatch as unresolved`() = withFixture { fixture ->
        fixture.mutateObservations { root ->
            root
                .changeCase("compile-file") { it.with("exitCode", JsonPrimitive(1)) }
                .changeCase("compile-c-standard") { it.with("stdout", blob("different stdout".encodeToByteArray())) }
        }
        val assessment = fixture.assess()
        assertEquals(2, assessment.mismatches.size)

        val partial = LlvmBehaviorMismatchLedgerV1Store.append(
            assessment,
            annotations = listOf(LlvmBehaviorMismatchAnnotationV1(assessment.mismatches.first().mismatchId, "accepted", "Reviewed fixture difference")),
        )
        assertEquals(2, partial.mismatchOccurrences)
        assertEquals(1, partial.acceptedAnnotationCount)
        assertEquals(1, partial.unresolvedAnnotationCount)
        val partialAnnotations = ledgerDocument(partial).events().single().array("annotations").map { it as JsonObject }
        assertEquals(setOf("caller-annotation", "generated-unresolved"), partialAnnotations.map { it.string("origin") }.toSet())
        val generated = partialAnnotations.single { it.string("origin") == "generated-unresolved" }
        assertEquals("unresolved", generated.string("disposition"))
        assertEquals("No adjudication was supplied; this mismatch remains unresolved.", generated.string("rationale"))

        val unannotated = LlvmBehaviorMismatchLedgerV1Store.append(assessment)
        assertEquals(2, unannotated.mismatchOccurrences)
        assertEquals(0, unannotated.acceptedAnnotationCount)
        assertEquals(2, unannotated.unresolvedAnnotationCount)
    }

    @Test
    fun `changed annotations append history and exact repetitions remain idempotent across all history`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("published")
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment)
        val originalFile = Files.readAllBytes(directory.resolve("ledger-0001.json"))
        val annotation = accepted(assessment, "Reviewed fixture difference")
        val second = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, listOf(annotation))

        assertEquals(2, second.eventCount)
        assertEquals(2, second.mismatchOccurrences)
        assertEquals(1, second.acceptedAnnotationCount)
        assertEquals(1, second.unresolvedAnnotationCount)
        assertNotEquals(first.ledgerSha256, second.ledgerSha256)
        assertContentEquals(originalFile, Files.readAllBytes(directory.resolve("ledger-0001.json")))

        val repeatLatest = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, second, listOf(annotation))
        val repeatEarlier = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, second)
        assertContentEquals(second.canonicalBytes, repeatLatest.canonicalBytes)
        assertContentEquals(second.canonicalBytes, repeatEarlier.canonicalBytes)
        assertEquals(setOf("ledger-0001.json", "ledger-0002.json"), ledgerFileNames(directory))
    }

    @Test
    fun `candidate revisions retain stable mismatch IDs and a later matching comparison keeps earlier failures`() = withFixture { fixture ->
        val firstAssessment = fixture.exitCodeMismatch()
        val first = LlvmBehaviorMismatchLedgerV1Store.append(firstAssessment)
        fixture.replaceCandidate("candidate revision two".encodeToByteArray())
        val secondAssessment = fixture.exitCodeMismatch()

        assertEquals(firstAssessment.mismatches.single().mismatchId, secondAssessment.mismatches.single().mismatchId)
        assertNotEquals(firstAssessment.assessmentSha256, secondAssessment.assessmentSha256)
        assertNotEquals(firstAssessment.candidateExecutableSha256, secondAssessment.candidateExecutableSha256)
        val second = LlvmBehaviorMismatchLedgerV1Store.append(
            secondAssessment,
            first,
            listOf(accepted(secondAssessment, "Accepted only for this fixture revision")),
        )
        fixture.replaceCandidate("candidate revision three".encodeToByteArray())
        val matchingAssessment = fixture.assess()
        assertTrue(matchingAssessment.mismatches.isEmpty())
        val third = LlvmBehaviorMismatchLedgerV1Store.append(matchingAssessment, second)

        assertEquals(3, third.eventCount)
        assertEquals(2, third.mismatchOccurrences)
        assertEquals(1, third.acceptedAnnotationCount)
        assertEquals(1, third.unresolvedAnnotationCount)
        assertFalse(third.releaseEligible)
        assertFalse(third.scoringAuthority)
        val events = ledgerDocument(third).events()
        assertContentEquals(firstAssessment.canonicalBytes, retainedAssessment(events[0]))
        assertContentEquals(secondAssessment.canonicalBytes, retainedAssessment(events[1]))
        assertContentEquals(matchingAssessment.canonicalBytes, retainedAssessment(events[2]))
        assertTrue(events[2].array("annotations").isEmpty())
        assertEquals(1, ledgerDocument(third).objectValue("summary").int("distinctMismatchIds"))
        assertEquals(3, ledgerDocument(third).objectValue("summary").int("distinctCandidateExecutables"))
    }

    @Test
    fun `same unavailable mismatch identity retains failure code per occurrence`() = withFixture { fixture ->
        fixture.mutateObservations { root ->
            root.changeCase("compile-file") { unavailableCase(it.string("id"), "not-run", "not-requested") }
        }
        val notRun = fixture.assess()
        val first = LlvmBehaviorMismatchLedgerV1Store.append(notRun)
        fixture.mutateObservations { root ->
            root.changeCase("compile-file") { unavailableCase(it.string("id"), "infrastructure-failed", "runner-failed") }
        }
        val infrastructureFailed = fixture.assess()
        assertEquals(notRun.mismatches.single().mismatchId, infrastructureFailed.mismatches.single().mismatchId)
        assertEquals("not-requested", notRun.mismatches.single().failureCode)
        assertEquals("runner-failed", infrastructureFailed.mismatches.single().failureCode)

        val second = LlvmBehaviorMismatchLedgerV1Store.append(infrastructureFailed, first)
        assertEquals(2, second.eventCount)
        assertEquals(2, second.unresolvedAnnotationCount)
        assertFalse(second.releaseEligible)
        assertFalse(second.scoringAuthority)
        val retained = ledgerDocument(second).events().map(::retainedAssessmentDocument)
        assertEquals("not-requested", (retained[0].array("mismatches").single() as JsonObject).string("failureCode"))
        assertEquals("runner-failed", (retained[1].array("mismatches").single() as JsonObject).string("failureCode"))
        assertEquals(1, retained[0].objectValue("summary").int("notRun"))
        assertEquals(0, retained[0].objectValue("summary").int("infrastructureFailed"))
        assertEquals(0, retained[1].objectValue("summary").int("notRun"))
        assertEquals(1, retained[1].objectValue("summary").int("infrastructureFailed"))
    }

    @Test
    fun `unknown duplicate invalid and blank annotations reject without publication`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val mismatchId = assessment.mismatches.single().mismatchId
        val directory = fixture.privateDirectory("published")
        val valid = accepted(assessment, "Reviewed fixture difference")
        val invalidLists = listOf(
            listOf(LlvmBehaviorMismatchAnnotationV1("clang-behavior-${"0".repeat(32)}", "accepted", "Unknown mismatch")),
            listOf(valid, valid),
            listOf(LlvmBehaviorMismatchAnnotationV1(mismatchId, "ignored", "Unsupported disposition")),
            listOf(LlvmBehaviorMismatchAnnotationV1(mismatchId, "accepted", "")),
            listOf(LlvmBehaviorMismatchAnnotationV1(mismatchId, "unresolved", " \t\n")),
            listOf(LlvmBehaviorMismatchAnnotationV1(mismatchId, "accepted", "contains\u0000NUL")),
            listOf(LlvmBehaviorMismatchAnnotationV1(mismatchId, "accepted", "é".repeat(2049))),
        )
        invalidLists.forEach { annotations ->
            assertFailsWith<IllegalArgumentException> {
                LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, annotations = annotations)
            }
            assertTrue(ledgerFileNames(directory).isEmpty())
        }
    }

    @Test
    fun `external digest pin and canonical encoding are required on reload`() = withFixture { fixture ->
        val ledger = LlvmBehaviorMismatchLedgerV1Store.append(fixture.exitCodeMismatch())
        val path = fixture.writePrivate("ledger.json", ledger.canonicalBytes)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorMismatchLedgerV1Store.verify(path, "0".repeat(64))
        }
        val noncanonical = ledger.canonicalBytes + "\n".encodeToByteArray()
        fixture.writePrivate("ledger.json", noncanonical)
        assertFailsWith<OracleArtifactException> {
            LlvmBehaviorMismatchLedgerV1Store.verify(path, OracleArtifacts.sha256(noncanonical))
        }
    }

    @Test
    fun `repinned schema summaries scope annotations and event mutations still reject`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val first = LlvmBehaviorMismatchLedgerV1Store.append(assessment)
        val second = LlvmBehaviorMismatchLedgerV1Store.append(assessment, first, listOf(accepted(assessment, "Reviewed difference")))
        val original = ledgerDocument(second)
        val mutations: List<(JsonObject) -> JsonObject> = listOf(
            { it.with("schemaVersion", JsonPrimitive(2)) },
            { it.with("releaseEligible", JsonPrimitive(true)) },
            { it.with("scoringAuthority", JsonPrimitive(true)) },
            { it.replaceObject("summary") { summary -> summary.with("acceptedAnnotations", JsonPrimitive(2)) } },
            { it.replaceObject("scope") { scope -> scope.with("ownershipSha256", JsonPrimitive("0".repeat(64))) } },
            { it.changeEvent(1) { event -> event.with("sequence", JsonPrimitive(3)) } },
            { it.changeEvent(1) { event -> event.with("previousLedgerSha256", JsonPrimitive("0".repeat(64))) } },
            { it.changeEvent(1) { event -> event.with("assessmentSha256", JsonPrimitive("0".repeat(64))) } },
            { it.changeEvent(1) { event -> event.with("annotations", JsonArray(emptyList())) } },
            { it.changeEvent(1) { event -> event.with("annotations", JsonArray(event.array("annotations") + event.array("annotations"))) } },
            { it.changeEvent(1) { event -> event.changeAnnotation { annotation -> annotation.with("mismatchId", JsonPrimitive("clang-behavior-${"0".repeat(32)}")) } } },
            { it.changeEvent(1) { event -> event.changeAnnotation { annotation -> annotation.with("rationale", JsonPrimitive(" ")) } } },
            { it.changeEvent(0) { event -> event.changeAnnotation { annotation -> annotation.with("disposition", JsonPrimitive("accepted")) } } },
            { it.with("events", JsonArray(it.events().reversed())) },
            { it.with("events", JsonArray(it.events() + it.events().last())) },
        )
        mutations.forEachIndexed { index, mutate ->
            val bytes = OracleJson.canonicalBytes(mutate(original), jsonLimits())
            val path = fixture.writePrivate("mutated-$index.json", bytes)
            assertFailsWith<IllegalArgumentException>("mutation $index") {
                LlvmBehaviorMismatchLedgerV1Store.verify(path, OracleArtifacts.sha256(bytes))
            }
        }
    }

    @Test
    fun `embedded comparison summary and cross paired comparison bytes reject after ledger repinning`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val ledger = ledgerDocument(LlvmBehaviorMismatchLedgerV1Store.append(assessment))
        val changedAssessment = assessmentDocument(assessment).replaceObject("summary") {
            it.with("mismatchRecords", JsonPrimitive(0))
        }
        val changedBytes = OracleJson.canonicalBytes(changedAssessment, jsonLimits())
        val changedDocument = ledger.changeEvent(0) { it.withRetainedAssessment(changedBytes) }
        val changedLedgerBytes = OracleJson.canonicalBytes(changedDocument, jsonLimits())
        val changedPath = fixture.writePrivate("changed-summary.json", changedLedgerBytes)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorMismatchLedgerV1Store.verify(changedPath, OracleArtifacts.sha256(changedLedgerBytes))
        }

        fixture.replaceCandidate("different candidate revision".encodeToByteArray())
        val anotherAssessment = fixture.exitCodeMismatch()
        val crossPairedDocument = ledger.changeEvent(0) { event ->
            event.with("assessmentBase64", JsonPrimitive(Base64.getEncoder().encodeToString(anotherAssessment.canonicalBytes)))
                .with("assessmentBytes", JsonPrimitive(anotherAssessment.canonicalBytes.size))
        }
        val crossPairedBytes = OracleJson.canonicalBytes(crossPairedDocument, jsonLimits())
        val crossPairedPath = fixture.writePrivate("cross-paired.json", crossPairedBytes)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorMismatchLedgerV1Store.verify(crossPairedPath, OracleArtifacts.sha256(crossPairedBytes))
        }
    }

    @Test
    fun `event bound fails whole append and leaves existing immutable publication intact`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("published")
        val limits = LlvmBehaviorMismatchLedgerLimitsV1(maximumEvents = 1)
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, limits = limits)
        val original = Files.readAllBytes(directory.resolve("ledger-0001.json"))
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorMismatchLedgerV1Store.publish(
                directory,
                assessment,
                first,
                listOf(accepted(assessment, "Changed disposition needs a new event")),
                limits,
            )
        }
        assertContentEquals(original, Files.readAllBytes(directory.resolve("ledger-0001.json")))
        assertEquals(setOf("ledger-0001.json"), ledgerFileNames(directory))
        val repeated = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, limits = limits)
        assertContentEquals(first.canonicalBytes, repeated.canonicalBytes)
    }

    @Test
    fun `publisher refuses replacing an occupied next revision`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("published")
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment)
        val occupiedPath = directory.resolve("ledger-0002.json")
        val occupiedBytes = "unrelated file must survive".encodeToByteArray()
        fixture.writePrivate(occupiedPath, occupiedBytes)
        assertFails {
            LlvmBehaviorMismatchLedgerV1Store.publish(
                directory,
                assessment,
                first,
                listOf(accepted(assessment, "Would create another revision")),
            )
        }
        assertContentEquals(occupiedBytes, Files.readAllBytes(occupiedPath))
        assertContentEquals(first.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0001.json")))
    }

    @Test
    fun `second descendant from stale prior cannot fork published lineage`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("published")
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment)
        val second = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, listOf(accepted(assessment, "First descendant")))
        assertFails {
            LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, listOf(accepted(assessment, "Competing descendant")))
        }
        assertContentEquals(second.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0002.json")))
        assertContentEquals(first.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0001.json")))
        assertEquals(setOf("ledger-0001.json", "ledger-0002.json"), ledgerFileNames(directory))
    }

    @Test
    fun `publisher rejects directory holes and alien names without mutating retained files`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val holeDirectory = fixture.privateDirectory("hole")
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(holeDirectory, assessment)
        val second = LlvmBehaviorMismatchLedgerV1Store.publish(
            holeDirectory,
            assessment,
            first,
            listOf(accepted(assessment, "Second event before the directory loses its first snapshot")),
        )
        Files.delete(holeDirectory.resolve("ledger-0001.json"))
        assertFails {
            LlvmBehaviorMismatchLedgerV1Store.publish(holeDirectory, assessment, second)
        }
        assertContentEquals(second.canonicalBytes, Files.readAllBytes(holeDirectory.resolve("ledger-0002.json")))
        assertEquals(setOf("ledger-0002.json"), ledgerFileNames(holeDirectory))

        val alienDirectory = fixture.privateDirectory("alien")
        val alienBytes = "unrelated directory entry".encodeToByteArray()
        val alienPath = fixture.writePrivate(alienDirectory.resolve("alien.json"), alienBytes)
        assertFails {
            LlvmBehaviorMismatchLedgerV1Store.publish(alienDirectory, assessment)
        }
        assertContentEquals(alienBytes, Files.readAllBytes(alienPath))
        assertTrue(ledgerFileNames(alienDirectory).isEmpty())
    }

    @Test
    fun `publisher fails immediately while another descriptor holds the directory lock`() = withFixture { fixture ->
        val assessment = fixture.exitCodeMismatch()
        val directory = fixture.privateDirectory("locked")
        val first = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment)
        val annotations = listOf(accepted(assessment, "A second event requires exclusive directory ownership"))
        LinuxFilesystemSyscalls.openRoot(directory).use { descriptor ->
            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(descriptor))
            try {
                val failure = assertFailsWith<IllegalArgumentException> {
                    LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, annotations)
                }
                assertTrue(failure.message.orEmpty().contains("already locked"), failure.message)
                assertContentEquals(first.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0001.json")))
                assertEquals(setOf("ledger-0001.json"), ledgerFileNames(directory))
            } finally {
                LinuxFilesystemSyscalls.unlock(descriptor)
            }
        }
        val second = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, first, annotations)
        assertEquals(2, second.eventCount)
        assertContentEquals(second.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0002.json")))
    }

    @Test
    fun `interrupted immutable publication recovers only the exact intended ledger`() {
        listOf(DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC, DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)
            .forEach { faultPoint ->
                withFixture { fixture ->
                    val assessment = fixture.exitCodeMismatch()
                    val expected = LlvmBehaviorMismatchLedgerV1Store.append(assessment)
                    val directory = fixture.privateDirectory("published")
                    assertFailsWith<SimulatedProcessDeath> {
                        LlvmBehaviorMismatchLedgerV1Store.publish(
                            directory,
                            assessment,
                            null,
                            emptyList(),
                            LlvmBehaviorMismatchLedgerLimitsV1(),
                            DescriptorBoundStateFaultInjector { observed -> if (observed == faultPoint) throw SimulatedProcessDeath() },
                        )
                    }
                    assertFails {
                        LlvmBehaviorMismatchLedgerV1Store.publish(
                            directory,
                            assessment,
                            annotations = listOf(accepted(assessment, "Different bytes cannot recover the interrupted publication")),
                        )
                    }
                    val recovered = LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment)
                    assertContentEquals(expected.canonicalBytes, recovered.canonicalBytes)
                    assertContentEquals(expected.canonicalBytes, Files.readAllBytes(directory.resolve("ledger-0001.json")))
                    assertFalse(Files.exists(directory.resolve(DescriptorBoundAtomicStateFile.temporaryName("ledger-0001.json"))))
                }
            }
    }

    @Test
    fun `cumulative rationale byte bound fails whole publication without erasing four preceding events`() = withFixture { fixture ->
        fixture.mutateObservations { root ->
            root.changeCase("help-driver") { case ->
                case.with("artifacts", JsonArray((0 until 256).map { presentArtifact("unexpected-${it.toString().padStart(3, '0')}.bin") }))
            }
        }
        val assessment = fixture.assess()
        assertEquals(256, assessment.mismatches.size)
        val directory = fixture.privateDirectory("published")
        val limits = LlvmBehaviorMismatchLedgerLimitsV1(maximumCumulativeRationaleBytes = 4L * 1024 * 1024)
        var ledger: LlvmBehaviorMismatchLedgerV1? = null
        repeat(4) { index ->
            ledger = LlvmBehaviorMismatchLedgerV1Store.publish(
                directory,
                assessment,
                ledger,
                annotations(assessment, index),
                limits,
            )
        }
        val previous = checkNotNull(ledger)
        assertEquals(4, previous.eventCount)
        assertEquals(4L * 1024 * 1024, ledgerDocument(previous).objectValue("summary").long("retainedRationaleBytes"))
        val priorBytes = Files.readAllBytes(directory.resolve("ledger-0004.json"))
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorMismatchLedgerV1Store.publish(directory, assessment, previous, annotations(assessment, 4), limits)
        }
        assertContentEquals(priorBytes, Files.readAllBytes(directory.resolve("ledger-0004.json")))
        assertEquals((1..4).map { "ledger-${it.toString().padStart(4, '0')}.json" }.toSet(), ledgerFileNames(directory))
    }

    @Test
    fun `integrity reader admits exact comparison v1 maximum bytes and mismatch population`() = withFixture { fixture ->
        // This raw retained projection exercises integrity admission only. It is never passed to
        // append, never creates a sealed comparison capability, and claims no candidate execution.
        val assessmentBytes = maximumRetainedProjection(assessmentDocument(fixture.assess()))
        assertEquals(16 * 1024 * 1024, assessmentBytes.size)
        val assessment = OracleJson.parseCanonical(assessmentBytes, jsonLimits()) as JsonObject
        OracleSchemas.validate("llvm-behavior-comparison-assessment", assessment)
        assertEquals(50_400, assessment.array("mismatches").size)
        val assessmentSha256 = OracleArtifacts.sha256(assessmentBytes)
        val rationale = "No adjudication was supplied; this mismatch remains unresolved."
        val annotations = JsonArray(assessment.array("mismatches").map { mismatch ->
            JsonObject(
                linkedMapOf(
                    "mismatchId" to (mismatch as JsonObject).getValue("mismatchId"),
                    "disposition" to JsonPrimitive("unresolved"),
                    "rationale" to JsonPrimitive(rationale),
                    "origin" to JsonPrimitive("generated-unresolved"),
                ),
            )
        })
        val eventId = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(
                JsonObject(
                    linkedMapOf(
                        "domain" to JsonPrimitive("decomp-llvm-mismatch-annotation-event-v1"),
                        "assessmentSha256" to JsonPrimitive(assessmentSha256),
                        "annotations" to annotations,
                    ),
                ),
                jsonLimits(),
            ),
        )
        val document = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "authority" to JsonPrimitive("integrity-only-retained-comparison-and-annotations-v1"),
                "releaseEligible" to JsonPrimitive(false),
                "scoringAuthority" to JsonPrimitive(false),
                "annotationAuthority" to JsonPrimitive("untrusted-metadata-only"),
                "scope" to JsonObject(
                    linkedMapOf(
                        "reference" to assessment.getValue("reference"),
                        "ownershipId" to assessment.objectValue("inputs").getValue("ownershipId"),
                        "ownershipSha256" to assessment.objectValue("inputs").getValue("ownershipSha256"),
                    ),
                ),
                "previousLedgerSha256" to JsonNull,
                "summary" to JsonObject(
                    linkedMapOf(
                        "annotationEvents" to JsonPrimitive(1),
                        "distinctAssessments" to JsonPrimitive(1),
                        "distinctCandidateExecutables" to JsonPrimitive(1),
                        "distinctMismatchIds" to JsonPrimitive(50_400),
                        "mismatchOccurrences" to JsonPrimitive(50_400),
                        "acceptedAnnotations" to JsonPrimitive(0),
                        "unresolvedAnnotations" to JsonPrimitive(50_400),
                        "retainedAssessmentBytes" to JsonPrimitive(assessmentBytes.size),
                        "retainedRationaleBytes" to JsonPrimitive(50_400L * rationale.encodeToByteArray().size),
                    ),
                ),
                "events" to JsonArray(
                    listOf(
                        JsonObject(
                            linkedMapOf(
                                "sequence" to JsonPrimitive(1),
                                "previousLedgerSha256" to JsonNull,
                                "eventId" to JsonPrimitive(eventId),
                                "assessmentSha256" to JsonPrimitive(assessmentSha256),
                                "assessmentBytes" to JsonPrimitive(assessmentBytes.size),
                                "assessmentBase64" to JsonPrimitive(Base64.getEncoder().encodeToString(assessmentBytes)),
                                "candidateExecutableSha256" to assessment.objectValue("candidateExecutable").getValue("sha256"),
                                "annotations" to annotations,
                            ),
                        ),
                    ),
                ),
            ),
        )
        OracleSchemas.validate("llvm-behavior-mismatch-ledger-v1", document)
        val bytes = OracleJson.canonicalBytes(document, jsonLimits())
        val path = fixture.writePrivate("maximum-retained-projection.json", bytes)
        val minimalLimits = LlvmBehaviorMismatchLedgerLimitsV1(
            maximumEvents = 1,
            maximumLedgerBytes = 40 * 1024 * 1024,
            maximumCumulativeAssessmentBytes = 16L * 1024 * 1024,
            maximumMismatchOccurrences = 50_400,
            maximumCumulativeRationaleBytes = 4L * 1024 * 1024,
        )
        val reloaded = LlvmBehaviorMismatchLedgerV1Store.verify(path, OracleArtifacts.sha256(bytes), minimalLimits)
        assertEquals(1, reloaded.eventCount)
        assertEquals(50_400, reloaded.mismatchOccurrences)
        assertEquals(50_400, reloaded.unresolvedAnnotationCount)
        assertEquals(0, reloaded.acceptedAnnotationCount)
        assertFalse(reloaded.releaseEligible)
        assertFalse(reloaded.scoringAuthority)
        assertEquals("integrity-only-retained-comparison-and-annotations-v1", reloaded.authority)
        assertContentEquals(bytes, reloaded.canonicalBytes)
    }

    private fun maximumRetainedProjection(base: JsonObject): ByteArray {
        val maximumBytes = 16 * 1024 * 1024
        val maximumMismatches = 50_400
        val owner = readCanonicalObject(OWNERSHIP).array("cases")
            .map { it as JsonObject }.single { it.string("id") == "help-driver" }.getValue("ownerSubsystem")
        fun mismatch(path: String): JsonObject = JsonObject(
            linkedMapOf(
                "mismatchId" to JsonPrimitive(
                    llvmBehaviorCandidateMismatchId(
                        EXPECTED_CORPUS_SHA256,
                        "help-driver",
                        LlvmBehaviorCandidateMismatchKind.UNEXPECTED_ARTIFACT,
                        path,
                    ),
                ),
                "caseId" to JsonPrimitive("help-driver"),
                "kind" to JsonPrimitive("unexpected-artifact"),
                "artifactPath" to JsonPrimitive(path),
                "ownerSubsystem" to owner,
                "failureCode" to JsonNull,
            ),
        )
        val projection = base.replaceObject("summary") { summary ->
            summary.with("matchingObserved", JsonPrimitive(47))
                .with("mismatchingObserved", JsonPrimitive(1))
                .with("mismatchRecords", JsonPrimitive(maximumMismatches))
        }
        val paths = (0 until maximumMismatches).map { "projection-${it.toString().padStart(5, '0')}" }
        val minimal = projection.with("mismatches", JsonArray(paths.map(::mismatch)))
        val remaining = maximumBytes - OracleJson.canonicalBytes(minimal, jsonLimits()).size
        assertTrue(remaining >= 0, "minimal retained projection exceeds comparison-v1 capacity")
        val perPathPadding = remaining / maximumMismatches
        val extraPadding = remaining % maximumMismatches
        val rows = paths.mapIndexed { index, path ->
            val padded = path + "p".repeat(perPathPadding + if (index < extraPadding) 1 else 0)
            assertTrue(padded.length <= 4096)
            mismatch(padded)
        }.sortedBy { it.string("mismatchId") }
        assertEquals(maximumMismatches, rows.map { it.string("mismatchId") }.toSet().size)
        return OracleJson.canonicalBytes(projection.with("mismatches", JsonArray(rows)), jsonLimits())
    }

    private fun annotations(assessment: LlvmBehaviorCandidateAssessment, eventIndex: Int): List<LlvmBehaviorMismatchAnnotationV1> =
        assessment.mismatches.map {
            val prefix = "Fixture annotation event $eventIndex: "
            LlvmBehaviorMismatchAnnotationV1(it.mismatchId, "unresolved", prefix + "r".repeat(4096 - prefix.length))
        }

    private class SimulatedProcessDeath : RuntimeException()

    private inner class Fixture(val root: Path, val executable: Path, val observations: Path, val ownership: Path) {
        fun assess(): LlvmBehaviorCandidateAssessment = LlvmBehaviorCandidateAssessmentVerifier.assess(
            PROFILE.resolve("behavior-corpus.json"),
            PROFILE.resolve("behavior-corpus-evidence.json"),
            PROFILE.resolve("diagnostic-matrix.json"),
            PROFILE.resolve("oracle-manifest.json"),
            executable,
            observations,
            ownership,
        )

        fun exitCodeMismatch(): LlvmBehaviorCandidateAssessment {
            mutateObservations { root -> root.changeCase("compile-file") { it.with("exitCode", JsonPrimitive(1)) } }
            return assess().also { assertEquals(1, it.mismatches.size) }
        }

        fun replaceCandidate(bytes: ByteArray) {
            writePrivate(executable, bytes)
            writePrivate(observations, matchingObservation(bytes))
        }

        fun mutateObservations(change: (JsonObject) -> JsonObject) {
            val changed = change(readCanonicalObject(observations))
            writePrivate(observations, OracleJson.canonicalBytes(changed, jsonLimits()))
        }

        fun privateDirectory(name: String): Path = root.resolve(name).also {
            Files.createDirectory(it, PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS))
        }

        fun writePrivate(name: String, bytes: ByteArray): Path = writePrivate(root.resolve(name), bytes)

        fun writePrivate(path: Path, bytes: ByteArray): Path = path.also {
            Files.write(it, bytes)
            Files.setPosixFilePermissions(it, PRIVATE_FILE_PERMISSIONS)
        }
    }

    private fun withFixture(action: (Fixture) -> Unit) {
        val buildDirectory = REPOSITORY_ROOT.resolve("build").also { Files.createDirectories(it) }
        val root = Files.createTempDirectory(
            buildDirectory,
            "llvm-mismatch-ledger-test-",
            PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
        )
        try {
            val executableBytes = "candidate executable fixture revision".encodeToByteArray()
            val executable = root.resolve("candidate-clang")
            val observations = root.resolve("candidate-observations.json")
            val ownership = root.resolve("behavior-case-ownership.json")
            Files.copy(OWNERSHIP, ownership, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(ownership, PRIVATE_FILE_PERMISSIONS)
            val fixture = Fixture(root, executable, observations, ownership)
            fixture.replaceCandidate(executableBytes)
            action(fixture)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun accepted(assessment: LlvmBehaviorCandidateAssessment, rationale: String): LlvmBehaviorMismatchAnnotationV1 =
        LlvmBehaviorMismatchAnnotationV1(assessment.mismatches.single().mismatchId, "accepted", rationale)

    private fun ledgerFileNames(directory: Path): Set<String> = Files.list(directory).use { paths ->
        paths.map { it.fileName.toString() }.filter { it.matches(Regex("ledger-[0-9]{4}\\.json")) }.toList().toSet()
    }

    private fun matchingObservation(executableBytes: ByteArray): ByteArray {
        val report = readCanonicalObject(PROFILE.resolve("behavior-corpus-evidence.json"))
        val cases = report.array("cases").map { raw ->
            val case = raw as JsonObject
            JsonObject(
                linkedMapOf(
                    "id" to case.getValue("id"),
                    "status" to JsonPrimitive("observed"),
                    "exitCode" to case.getValue("exitCode"),
                    "stdout" to JsonObject(case.objectValue("stdout").filterKeys { it != "normalizations" }),
                    "stderr" to JsonObject(case.objectValue("stderr").filterKeys { it != "normalizations" }),
                    "artifacts" to case.getValue("artifacts"),
                ),
            )
        }
        val document = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "reference" to JsonObject(
                    linkedMapOf(
                        "corpusId" to JsonPrimitive("clang-22-1-6-driver-behavior"),
                        "corpusSha256" to JsonPrimitive(EXPECTED_CORPUS_SHA256),
                        "reportSha256" to JsonPrimitive(EXPECTED_REPORT_SHA256),
                        "diagnosticMatrixSha256" to JsonPrimitive(EXPECTED_MATRIX_SHA256),
                        "diagnosticMatrixSelfSha256" to JsonPrimitive(EXPECTED_MATRIX_SELF_SHA256),
                        "artifactManifestSha256" to JsonPrimitive(EXPECTED_MANIFEST_SHA256),
                        "sandboxSha256" to JsonPrimitive(EXPECTED_SANDBOX_SHA256),
                    ),
                ),
                "candidateExecutable" to JsonObject(
                    linkedMapOf(
                        "bytes" to JsonPrimitive(executableBytes.size),
                        "sha256" to JsonPrimitive(OracleArtifacts.sha256(executableBytes)),
                    ),
                ),
                "cases" to JsonArray(cases),
            ),
        )
        OracleSchemas.validate("llvm-behavior-candidate-observations", document)
        return OracleJson.canonicalBytes(document, jsonLimits())
    }

    private fun blob(content: ByteArray): JsonObject = JsonObject(
        linkedMapOf(
            "bytes" to JsonPrimitive(content.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(content)),
            "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(content)),
        ),
    )

    private fun presentArtifact(path: String): JsonObject = JsonObject(
        linkedMapOf(
            "path" to JsonPrimitive(path),
            "present" to JsonPrimitive(true),
            "bytes" to JsonPrimitive(0),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(ByteArray(0))),
            "base64" to JsonPrimitive(""),
            "mode" to JsonPrimitive("0o600"),
        ),
    )

    private fun unavailableCase(id: String, status: String, failureCode: String): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "status" to JsonPrimitive(status),
            "failureCode" to JsonPrimitive(failureCode),
        ),
    )

    private fun readCanonicalObject(path: Path): JsonObject =
        OracleJson.parseCanonical(Files.readAllBytes(path), jsonLimits()) as JsonObject

    private fun ledgerDocument(ledger: LlvmBehaviorMismatchLedgerV1): JsonObject =
        OracleJson.parseCanonical(ledger.canonicalBytes, jsonLimits()) as JsonObject

    private fun assessmentDocument(assessment: LlvmBehaviorCandidateAssessment): JsonObject =
        OracleJson.parseCanonical(assessment.canonicalBytes, jsonLimits()) as JsonObject

    private fun retainedAssessment(event: JsonObject): ByteArray =
        Base64.getDecoder().decode(event.string("assessmentBase64"))

    private fun retainedAssessmentDocument(event: JsonObject): JsonObject =
        OracleJson.parseCanonical(retainedAssessment(event), jsonLimits()) as JsonObject

    private fun jsonLimits(): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = 64 * 1024 * 1024,
        maximumCanonicalBytes = 64 * 1024 * 1024,
        maximumDepth = 96,
        maximumNodes = 500_000,
        maximumStringBytes = 64 * 1024 * 1024,
        maximumTotalStringBytes = 64 * 1024 * 1024,
        maximumNumberCharacters = 64,
    )

    private fun JsonObject.changeCase(id: String, change: (JsonObject) -> JsonObject): JsonObject =
        with("cases", JsonArray(array("cases").map { raw ->
            val case = raw as JsonObject
            if (case.string("id") == id) change(case) else case
        }))

    private fun JsonObject.events(): List<JsonObject> = array("events").map { it as JsonObject }

    private fun JsonObject.changeEvent(index: Int, change: (JsonObject) -> JsonObject): JsonObject =
        with("events", JsonArray(events().mapIndexed { current, event -> if (current == index) change(event) else event }))

    private fun JsonObject.changeAnnotation(change: (JsonObject) -> JsonObject): JsonObject =
        with("annotations", JsonArray(array("annotations").map { change(it as JsonObject) }))

    private fun JsonObject.withRetainedAssessment(bytes: ByteArray): JsonObject =
        with("assessmentBytes", JsonPrimitive(bytes.size))
            .with("assessmentBase64", JsonPrimitive(Base64.getEncoder().encodeToString(bytes)))
            .with("assessmentSha256", JsonPrimitive(OracleArtifacts.sha256(bytes)))

    private fun JsonObject.replaceObject(name: String, change: (JsonObject) -> JsonObject): JsonObject =
        with(name, change(objectValue(name)))

    private fun JsonObject.with(name: String, value: JsonElement): JsonObject = JsonObject(this + (name to value))
    private fun JsonObject.objectValue(name: String): JsonObject = getValue(name) as JsonObject
    private fun JsonObject.array(name: String): JsonArray = getValue(name) as JsonArray
    private fun JsonObject.string(name: String): String = (getValue(name) as JsonPrimitive).content
    private fun JsonObject.int(name: String): Int = string(name).toInt()
    private fun JsonObject.long(name: String): Long = string(name).toLong()

    private companion object {
        val REPOSITORY_ROOT: Path = Path.of("").toAbsolutePath().normalize()
        val PROFILE: Path = REPOSITORY_ROOT.resolve("oracle/llvm/22.1.6")
        val OWNERSHIP: Path = PROFILE.resolve("behavior-case-ownership.json")
        val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
        val PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
        const val EXPECTED_CORPUS_SHA256 = "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b"
        const val EXPECTED_REPORT_SHA256 = "e9595bfd941c406d2c8fff618986e60dc0b810f1c384848b3ba540020ca00a6f"
        const val EXPECTED_MATRIX_SHA256 = "9e3b3223e014de49e0df50892556ae4649f819d5571751378ed9bfd12d684b2d"
        const val EXPECTED_MATRIX_SELF_SHA256 = "fc8145038141fca072d506391b4d93311aa3842ea6bfa088285c5dce7943ed3b"
        const val EXPECTED_MANIFEST_SHA256 = "5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40"
        const val EXPECTED_SANDBOX_SHA256 = "e4991450d10843e2fce6bc430a8876682fd831b3c4768b7fb757d7ee158638fa"
    }
}
