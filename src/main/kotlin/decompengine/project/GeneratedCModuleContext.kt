package decompengine.project

/** Select recovered declarations here, where C interface policy belongs, before provider dispatch. */
internal object GeneratedCModuleContext {
    fun select(request: ModuleReconstructionRequest): ModulePromptContext {
        val model = request.model
        val module = request.module
        val localIds = module.functionIds.toSet()
        val functions = model.functions.associateBy { it.id }
        val globals = model.globals.associateBy { it.id }
        val localFunctions = module.functionIds.map(functions::getValue)
        val incoming = model.functions.filter { it.id !in localIds && it.calls.any(localIds::contains) }.sortedBy { it.id }
        val outgoingIds = localFunctions.flatMap { it.calls }.filter { it !in localIds }.toSortedSet()
        val outgoing = outgoingIds.mapNotNull(functions::get)
        val referencedGlobalIds = localFunctions.flatMap { it.referencedGlobals }.toSortedSet()
        val requiredGlobals = (module.globalIds + referencedGlobalIds).distinct().mapNotNull(globals::get)
        val selectedFunctions = (localFunctions + incoming + outgoing).distinctBy { it.id }
        val typeEvidence = selectedFunctions.map { it.prototype } +
            localFunctions.mapNotNull { it.decompiledC } + requiredGlobals.map { it.type } +
            module.globalIds.mapNotNull { globals.getValue(it).initializer }
        val types = selectRequiredGeneratedCTypes(model.types, typeEvidence)
        val selectedModel = model.copy(functions = selectedFunctions, globals = requiredGlobals, types = types)
        val nonlocalRequiredIds = outgoing.map { it.id }.toSet() + requiredGlobals.map { it.id }.filter { it !in module.globalIds }
        require(nonlocalRequiredIds.isEmpty() || request.modulePlan != null) {
            "cross-module interface selection requires the recovered module ownership plan"
        }
        val plan = request.modulePlan ?: ModulePlan(modules = listOf(module))
        require(plan.modules.singleOrNull { it.id == module.id } == module) {
            "module context ownership must match the planned module"
        }
        val functionOwners = plan.modules.flatMap { owner -> owner.functionIds.map { it to owner.id } }.toMap()
        val globalOwners = plan.modules.flatMap { owner -> owner.globalIds.map { it to owner.id } }.toMap()
        nonlocalRequiredIds.forEach { id ->
            require(id in functionOwners || id in globalOwners) { "required recovered entity has no module owner: $id" }
        }
        val selectedFunctionIds = selectedFunctions.map { it.id }.toSet()
        val selectedGlobalIds = requiredGlobals.map { it.id }.toSet()
        val selectedTypeIds = types.map { it.id }.toSet()
        val selectedPlan = plan.copy(modules = plan.modules.map { owner -> owner.copy(
            functionIds = owner.functionIds.filter(selectedFunctionIds::contains),
            globalIds = owner.globalIds.filter(selectedGlobalIds::contains),
            typeIds = owner.typeIds.filter(selectedTypeIds::contains),
        ) })
        val selectedModule = selectedPlan.modules.single { it.id == module.id }
        val rendering = GeneratedCProjectRendering(selectedModel, selectedPlan)
        val layout = request.profile.layout
        val interfaces = linkedMapOf(
            layout.declaration("shared-interface").materialize() to rendering.sharedInterface(),
            module.headerPath to rendering.moduleInterface(selectedModule),
            layout.declaration("module-private-interface").materialize(mapOf("module" to module.id)) to
                rendering.privateInterface(selectedModule),
        )
        val outgoingSet = outgoing.map { it.id }.toSet()
        val nonlocalGlobalSet = requiredGlobals.map { it.id }.filter { it !in module.globalIds }.toSet()
        plan.modules.filter { it.id != module.id }.sortedBy { it.id }.forEach { owner ->
            val required = owner.copy(
                functionIds = owner.functionIds.filter(outgoingSet::contains),
                globalIds = owner.globalIds.filter(nonlocalGlobalSet::contains),
                typeIds = emptyList(),
            )
            if (required.functionIds.isNotEmpty() || required.globalIds.isNotEmpty()) {
                interfaces[owner.headerPath] = rendering.moduleInterface(required)
            }
        }
        val base = GeneratedCModulePrompt.render(request)
        val graph = buildString {
            append("\n\nRecovered graph context (identity and interface evidence, not additional implementation ownership):")
            append("\nincoming callers into this module:\n")
            append(incoming.joinToString("\n") { caller ->
                "${caller.id} @ 0x${caller.address.toString(16)}; name=${caller.name}; prototype=${caller.prototype}; " +
                    "calls owned functions=${caller.calls.filter(localIds::contains).sorted()}; status=${caller.status.name.lowercase()}"
            }.ifBlank { "<none recovered; absence is not proof of no callers>" })
            append("\n\noutgoing callees from this module:\n")
            append(outgoingIds.joinToString("\n") { id ->
                val callee = functions[id]
                if (callee == null) "$id; interface unavailable in recovered model" else
                    "${callee.id} @ 0x${callee.address.toString(16)}; name=${callee.name}; prototype=${callee.prototype}; " +
                        "owner=${functionOwners[id] ?: "unavailable"}; status=${callee.status.name.lowercase()}"
            }.ifBlank { "<none recovered; absence is not proof of no calls>" })
            append("\n\nreferenced globals outside this module:\n")
            append(referencedGlobalIds.filter { it !in module.globalIds }.joinToString("\n") { id ->
                val global = globals[id]
                if (global == null) "$id; interface unavailable in recovered model" else
                    "${global.id} @ 0x${global.address.toString(16)}; name=${global.name}; type=${global.type}; " +
                        "owner=${globalOwners[id] ?: "unavailable"}; status=${global.status.name.lowercase()}"
            }.ifBlank { "<none recovered>" })
        }
        return ModulePromptContext(
            ModulePromptContent(base.objective +
                "\nThe supplied interface snapshots are your complete readable interface context. Replace the owned source " +
                "from this evidence; existing source and other project files are not readable. Incoming callers are " +
                "context only; implement only the owned functions and globals.", base.evidence + graph),
            interfaces,
        )
    }
}
