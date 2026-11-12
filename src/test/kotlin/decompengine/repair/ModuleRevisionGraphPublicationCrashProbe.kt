package decompengine.repair

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.nio.file.Path

/** Halts at the non-atomic syscall/fsync boundary to qualify schema-6 restart roll-forward. */
internal object ModuleRevisionGraphPublicationCrashProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size in 2..4)
        val mode = arguments.getOrNull(2) ?: "after-exchange"
        val targetIndex = arguments.getOrNull(3)?.toInt()
        fun matches(index: Int): Boolean = targetIndex == null || targetIndex == index
        if (mode == "create-undecided-stage" || mode == "create-undecided-stage-intent" ||
            mode == "decision-prevalidated" || mode == "decision-exchanged"
        ) {
            val project = Path.of(arguments[0])
            fun decisionIsPublished(): Boolean = runCatching {
                val root = Json.parseToJsonElement(
                    java.nio.file.Files.readString(project.resolve("reports/repair-revisions/graph.json")),
                ).jsonObject
                val pending = root["pending"] as? JsonObject ?: return@runCatching false
                pending["acceptanceDecision"] is JsonObject
            }.getOrDefault(false)
            val targets = arguments[1].split(',').also {
                val minimum = if (mode.startsWith("decision-")) 1 else 2
                require(it.size >= minimum && it == it.distinct().sorted())
            }
            val candidates = targets.associateWith { relative ->
                val parts = relative.split('/')
                LinuxFilesystemSyscalls.openRoot(project).use { root ->
                    var parent = root
                    val opened = mutableListOf<decompengine.acp.LinuxDescriptor>()
                    try {
                        parts.dropLast(1).forEach { segment ->
                            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                            opened += parent
                        }
                        val source = requireNotNull(
                            LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last()),
                        )
                        source.use { held ->
                            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(held).use {
                                LinuxFilesystemSyscalls.readWithoutAtime(it, 1_048_576)
                            }
                        }
                    } finally {
                        opened.asReversed().forEach(decompengine.acp.LinuxDescriptor::close)
                    }
                } + "\n/* child crash candidate */\n".toByteArray()
            }
            var armed = false
            ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    val stop = when (mode) {
                        "create-undecided-stage" -> point is ModuleRevisionFaultPoint.AfterPublicationStage &&
                            point.path == targets.first() && matches(point.index)
                        "create-undecided-stage-intent" -> point is ModuleRevisionFaultPoint.AfterPublicationStageIntentPersist &&
                            point.path == targets.first() && matches(point.index)
                        "decision-prevalidated" -> point == ModuleRevisionFaultPoint.Schema6DecisionPrevalidated
                        else -> point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                            point.scope == "revision-state" && point.name == "graph.json" && decisionIsPublished()
                    }
                    if (armed && stop) {
                        Runtime.getRuntime().halt(86)
                    }
                },
            ).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(
                    ProcessInput("schema-six-undecided-crash", emptyList(), byteArrayOf(0)),
                ))
                graph.beginRun(maximumAttempts = 4, maximumWallMillis = 60_000)
                val original = sha256("child crash original binary".toByteArray())
                graph.bindOriginalBinary(original)
                graph.bindExpectedObservations(sha256("child crash expected observations".toByteArray()))
                val metadata = RevisionRepairMetadata(
                    iterationIndex = 1,
                    failureKind = "compile",
                    prompt = "schema-six child crash at decision boundary",
                    summary = null,
                    retainedRegressionIds = corpus.inputs.map { it.id },
                    before = null,
                    regressionCorpusSha256 = corpus.sha256,
                    publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
                )
                val attempt = graph.beginAttempt(targets, metadata)
                graph.installCandidate(attempt, candidates)
                armed = true
                val snapshot = graph.snapshot
                val proof = RepairValidationProof(
                    sourceRevisionSha256 = repairCandidateSourceSha256(graph.candidateSources(attempt)),
                    profileSha256 = snapshot.profileSha256,
                    indexSha256 = snapshot.indexSha256,
                    regressionCorpusSha256 = corpus.sha256,
                    originalBinarySha256 = original,
                    rebuiltBinarySha256 = sha256("child crash rebuilt binary".toByteArray()),
                    runtimeSha256 = sha256("child crash runtime".toByteArray()),
                    evidenceSha256 = sha256("child crash evidence".toByteArray()),
                    cleanupVerified = true,
                    assurance = RepairValidationAssurance.STRICT_CONTAINED,
                )
                graph.accept(attempt, RepairEvidence("valid", "must halt at selected decision boundary"), proof)
            }
            kotlin.system.exitProcess(87)
        }
        ModuleRevisionGraph.openForTesting(
            Path.of(arguments[0]),
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                val crash = when (mode) {
                    "after-exchange" -> point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                        point.phase == "schema6-roll-forward" && point.path == arguments[1] && matches(point.index)
                    "after-target-sync" -> point is ModuleRevisionFaultPoint.AfterPublicationTargetDirectorySync &&
                        point.phase == "schema6-roll-forward" && point.path == arguments[1] && matches(point.index)
                    "after-move" -> point is ModuleRevisionFaultPoint.AfterPublicationMove &&
                        point.phase == "schema6-roll-forward" && point.path == arguments[1] && matches(point.index)
                    "after-recovered-persist" -> point == ModuleRevisionFaultPoint.AfterRecoveredAcceptancePersist
                    else -> error("unknown publication crash mode: $mode")
                }
                if (crash) {
                    Runtime.getRuntime().halt(86)
                }
            },
        ).use { }
        kotlin.system.exitProcess(87)
    }
}
