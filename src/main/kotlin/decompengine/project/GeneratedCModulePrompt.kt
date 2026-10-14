package decompengine.project

/** Generated-C evidence formatting and implementation instructions; workflow authority stays outside. */
internal object GeneratedCModulePrompt {
    fun render(request: ModuleReconstructionRequest): ModulePromptContent {
        val target = request.module.sourcePath
        val localFunctions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val localGlobals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val byteEvidence = renderByteEvidence(localGlobals)
        val functionEvidence = localFunctions.joinToString("\n\n") { function ->
            "${function.id} @ 0x${function.address.toString(16)}\nprototype: ${function.prototype}\n" +
                "calls: ${function.calls.sorted()}\nglobals: ${function.referencedGlobals.sorted()}\n" +
                "strings: ${function.strings.sorted()}\ndecompilation:\n${function.decompiledC ?: "<unavailable>"}"
        }
        val globalEvidence = localGlobals.joinToString("\n") { global ->
            "${global.id} @ 0x${global.address.toString(16)}: ${global.type} ${global.name}; " +
                "initializer=${global.initializer ?: "<unavailable>"}; status=${global.status.name.lowercase()}" +
                "\n" + byteEvidence.getValue(global.id)
        }
        val evidence = buildString {
            append("module: ").append(request.module.id).append('\n')
            append("ownership evidence: ").append(request.module.boundaryEvidence.sorted()).append("\n\n")
            append("functions:\n").append(functionEvidence.ifBlank { "<none>" })
            append("\n\nglobals:\n").append(globalEvidence.ifBlank { "<none>" })
        }
        val provenanceIds = (request.module.functionIds + request.module.globalIds).sorted()
        val acceptance = """
            The workflow validates your exact source bytes against the returned change set and owned entity IDs.
            Preserve all required function and global definitions and use only declared shared interfaces.
            Compiler gate (run by the workflow): ${ReconstructionCompilationPolicies.resolve(request.profile).command(request.profile, target).joinToString(" ")}
            Compiler warnings are errors. A completed agent turn is accepted only after policy and compiler validation.
            Full-project build and behavioral validation remain separate release gates.
        """.trimIndent()
        val objective = """
            Reconstruct exactly one C implementation unit at $target.
            Preserve recovered behavior and suspicious operations. Do not invent file paths or edit headers.
            Edit $target in the authorized workspace and keep provenance comments containing every owned entity ID:
            ${provenanceIds.joinToString(", ")}
            Do not use generic return-value placeholders or undefined decompiler types. If evidence is insufficient,
            stop without claiming completion so the module is recorded as explicitly unresolved.
        """.trimIndent() + "\n\n" + acceptance
        return ModulePromptContent(objective, evidence)
    }

    /** Bound raw input before constructing the complete prompt or invoking an agent. */
    private fun renderByteEvidence(globals: List<RecoveredGlobal>): Map<String, String> {
        var decodedBytes = 0L
        var renderedBytes = 0L
        val rendered = linkedMapOf<String, String>()
        for (global in globals) {
            val value = global.byteEvidence
            if (value != null) {
                ReferencedDataByteEvidenceJson.validate(value)
                for (window in value.windows) for (segment in window.segments) {
                    if (segment.availability == "available") {
                        decodedBytes = Math.addExact(decodedBytes, segment.length.toLong())
                        require(decodedBytes <= ReferencedDataByteEvidenceJson.MAXIMUM_PROMPT_DECODED_BYTES) {
                            "module referenced byte evidence decoded-byte prompt bound exceeded"
                        }
                    }
                }
            }
            val text = if (value == null) {
                "recovered input windows: <unavailable in historical model>"
            } else {
                "recovered input windows (non-authoritative; no object extent, type or initializer semantics): " +
                    ReferencedDataByteEvidenceJson.render(value)
            }
            renderedBytes = Math.addExact(renderedBytes, text.toByteArray(Charsets.UTF_8).size.toLong())
            require(renderedBytes <= ReferencedDataByteEvidenceJson.MAXIMUM_PROMPT_RENDERED_BYTES) {
                "module referenced byte evidence rendered-text prompt bound exceeded"
            }
            rendered[global.id] = text
        }
        return rendered
    }
}
