package decompengine.oracle.fulltree

import java.nio.file.Path
import kotlin.system.exitProcess

/** Thin JVM entry point replacing `verify-llvm-full-tree-scope.py`. */
object FullTreeScopeVerifierCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree scope verification") {
        val options = ControlArguments.parse(arguments)
        val scope = FullTreeScopeControl.load(
            options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
        )
        options.requireConsumed()
        println("verified full-tree scope: ${scope.document.controlObject("oracle").controlString("id")}")
    }
}

/** Thin JVM entry point replacing `generate-llvm-full-tree-inventory.py`. */
object FullTreeInventoryGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree inventory generation") {
        val options = ControlArguments.parse(arguments)
        val scope = FullTreeScopeControl.load(
            options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
        )
        val result = FullTreeInventoryControl.generateAndPublish(
            richArtifact = options.requiredPath("rich-artifact"),
            scope = scope,
            output = options.requiredPath("output"),
            maximumWorkers = options.integer("workers", 1),
        )
        options.requireConsumed()
        val counts = result.inventory.controlObject("counts")
        println(
            "wrote ${counts.controlLong("compilationUnits")} units in ${counts.controlLong("shards")} shards",
        )
    }
}

/** Thin JVM entry point replacing `generate-llvm-full-tree-source-inventory.py`. */
object FullTreeSourceInventoryGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree source inventory generation") {
        val options = ControlArguments.parse(arguments)
        val scope = FullTreeScopeControl.load(
            options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
        )
        val result = FullTreeSourceInventoryControl.generateAndPublish(
            archive = options.requiredPath("archive"),
            scope = scope,
            buildRecordPath = options.path("build-record", DEFAULT_PROFILE.resolve("build-record.json")),
            inventoryPath = options.path("inventory", DEFAULT_PROFILE.resolve("full-tree-inventory.json")),
            output = options.requiredPath("output"),
            maximumWorkers = options.integer("workers", 1),
        )
        options.requireConsumed()
        println(result.report.controlObject("counts"))
    }
}

/** Kotlin/JVM source-boundary planning authority; it deliberately emits no entity or header claims. */
object FullTreePlanningInventoryGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree planning inventory generation") {
        val options = ControlArguments.parse(arguments)
        val result = FullTreePlanningInventoryControl.generateAndPublish(
            scopePath = options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            sourceLockPath = options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            artifactManifestPath = options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
            buildRecordPath = options.path("build-record", DEFAULT_PROFILE.resolve("build-record.json")),
            inventoryPath = options.path("inventory", DEFAULT_PROFILE.resolve("full-tree-inventory.json")),
            sourceInventoryPath = options.path(
                "source-inventory",
                DEFAULT_PROFILE.resolve("full-tree-source-inventory.json"),
            ),
            output = options.requiredPath("output"),
        )
        options.requireConsumed()
        println(
            "wrote ${result.registry.sourceModules.size} source modules and " +
                "${result.registry.sourceOnlyUnits.size} source-only exclusions",
        )
    }
}

/** Kotlin/JVM generation of the explicitly incomplete A14 header-plan prerequisite envelope. */
object FullTreeHeaderPlanReadinessGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree header-plan readiness generation") {
        val options = ControlArguments.parse(arguments)
        val result = FullTreeHeaderPlanReadinessControl.generateAndPublish(
            sourceArchivePath = options.requiredPath("archive"),
            scopePath = options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            sourceLockPath = options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            artifactManifestPath = options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
            buildRecordPath = options.path("build-record", DEFAULT_PROFILE.resolve("build-record.json")),
            inventoryPath = options.path("inventory", DEFAULT_PROFILE.resolve("full-tree-inventory.json")),
            sourceInventoryPath = options.path(
                "source-inventory",
                DEFAULT_PROFILE.resolve("full-tree-source-inventory.json"),
            ),
            planningInventoryPath = options.path(
                "planning-inventory",
                DEFAULT_PROFILE.resolve("full-tree-planning-inventory.json"),
            ),
            output = options.requiredPath("output"),
        )
        options.requireConsumed()
        println(
            "wrote incomplete readiness for ${result.sourceModules.size} modules, " +
                "${result.sourceOnlyUnits.size} source-only exclusions, and " +
                "${result.authenticatedSourceHeaderCandidatePaths.size} authenticated source-header candidates",
        )
    }
}

/** Kotlin/JVM validation of a selective, integrity-verified, unreceipted generated-tree snapshot. */
object FullTreeGeneratedFileInventoryGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) = controlCli("full-tree generated-file inventory generation") {
        val options = ControlArguments.parse(arguments)
        val result = FullTreeGeneratedFileInventoryControl.generateAndPublish(
            generatedTreeArchivePath = options.requiredPath("generated-archive"),
            generatedProvenancePath = options.requiredPath("generated-provenance"),
            scopePath = options.path("scope", DEFAULT_PROFILE.resolve("full-tree-scope.json")),
            sourceLockPath = options.path("source-lock", DEFAULT_PROFILE.resolve("source-lock.json")),
            artifactManifestPath = options.path("manifest", DEFAULT_PROFILE.resolve("oracle-manifest.json")),
            buildRecordPath = options.path("build-record", DEFAULT_PROFILE.resolve("build-record.json")),
            inventoryPath = options.path("inventory", DEFAULT_PROFILE.resolve("full-tree-inventory.json")),
            sourceInventoryPath = options.path(
                "source-inventory",
                DEFAULT_PROFILE.resolve("full-tree-source-inventory.json"),
            ),
            planningInventoryPath = options.path(
                "planning-inventory",
                DEFAULT_PROFILE.resolve("full-tree-planning-inventory.json"),
            ),
            output = options.requiredPath("output"),
        )
        options.requireConsumed()
        println(
            "wrote integrity-verified unreceipted snapshot for " +
                "${result.registry.generatedHeaders.size} generated headers and " +
                "${result.registry.generatedTranslationUnits.size} A13 generated translation units",
        )
    }
}

private inline fun controlCli(label: String, action: () -> Unit) {
    try {
        action()
    } catch (failure: Exception) {
        System.err.println("$label failed: ${failure.message}")
        exitProcess(1)
    }
}

private class ControlArguments private constructor(private val values: MutableMap<String, String>) {
    fun requiredPath(name: String): Path = values.remove(name)?.let { value -> Path.of(value) }
        ?: throw FullTreeControlException("missing required --$name")

    fun path(name: String, default: Path): Path = values.remove(name)?.let { value -> Path.of(value) } ?: default

    fun integer(name: String, default: Int): Int {
        val value = values.remove(name) ?: return default
        return value.toIntOrNull() ?: throw FullTreeControlException("--$name must be an integer")
    }

    fun requireConsumed() {
        if (values.isNotEmpty()) throw FullTreeControlException("unknown option --${values.keys.first()}")
    }

    companion object {
        fun parse(arguments: Array<String>): ControlArguments {
            if (arguments.size % 2 != 0) throw FullTreeControlException("options must be --name value pairs")
            val values = linkedMapOf<String, String>()
            arguments.asList().chunked(2).forEach { (rawName, value) ->
                if (!rawName.matches(Regex("--[a-z][a-z-]*"))) {
                    throw FullTreeControlException("invalid option name $rawName")
                }
                val name = rawName.removePrefix("--")
                if (values.put(name, value) != null) throw FullTreeControlException("duplicate option $rawName")
            }
            return ControlArguments(values)
        }
    }
}

private val DEFAULT_PROFILE: Path = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
