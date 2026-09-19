package decompengine.project

/** Ninja owns compilation/link scheduling; interface and candidate policy remains reusable C. */
internal class GeneratedCNinjaProjectRendering(model: RecoveredProgramModel, plan: ModulePlan) :
    ProjectRendering by GeneratedCProjectRendering(model, plan) {
    override fun buildDefinition(sources: List<String>, profile: ReconstructionProfile): String {
        val compiler = profile.adapterConfiguration.getValue("compiler-driver").single()
        val flags = profile.adapterConfiguration.getValue("compiler-flags")
        ProjectBuildConfiguration(compilerExecutable = compiler, cFlags = flags)
        require(sources.isNotEmpty() && sources == sources.distinct().sorted())
        require(sources.all { it.matches(Regex("src/[A-Za-z0-9_./+-]+\\.c")) && ".." !in it.split('/') }) {
            "Ninja generated-C sources must use normalized source paths"
        }
        val objects = sources.map { "build/" + it.removePrefix("src/").removeSuffix(".c") + ".o" }
        return """
            ninja_required_version = 1.3
            builddir = build
            cc = $compiler
            cflags = ${flags.joinToString(" ")}
            mappings = "-ffile-prefix-map=${'$'}${'$'}PWD=." "-fdebug-prefix-map=${'$'}${'$'}PWD=." "-fmacro-prefix-map=${'$'}${'$'}PWD=."
            rule verify_sources
              command = test "${'$'}${'$'}(find src -type f -name '*.c' | LC_ALL=C sort | tr '\n' ' ')" = '${sources.joinToString(" ")} '
              description = [inputs] Verify owned source inventory
            build verify-sources: verify_sources
            rule compile
              command = ${'$'}cc ${'$'}cflags ${'$'}mappings -MMD -MF ${'$'}out.d -c ${'$'}in -o ${'$'}out
              depfile = ${'$'}out.d
              deps = gcc
              description = [compile] ${'$'}in -> ${'$'}out
            rule link
              command = ${'$'}cc ${'$'}cflags ${'$'}mappings ${'$'}in -o ${'$'}out
              description = [link] ${'$'}out

        """.trimIndent() + "\n" + sources.zip(objects).joinToString("\n") { (source, objectPath) ->
            "build $objectPath: compile $source || verify-sources"
        } + "\nbuild build/reconstructed: link ${objects.joinToString(" ")}\ndefault build/reconstructed\n"
    }
}
