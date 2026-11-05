package decompengine.project

/** Preserve declared C types. Only the function declarator's identifier may be renamed. */
internal fun normalizedPrototype(function: RecoveredFunction): String = recoveredDeclaration(function).prototype

internal class GeneratedCFunctionDeclaration(
    private val entityId: String,
    val prototype: String,
    val parameterNames: List<String>,
    val hasUnnamedParameters: Boolean,
    val explicitNoParameters: Boolean,
    val hasInternalLinkage: Boolean,
    val hasInlineSpecifier: Boolean,
    val hasExternSpecifier: Boolean,
    private val noReturn: Boolean,
    private val returnKind: GeneratedCTypeKind,
    private val resultDeclaration: (String) -> String,
    private val zeroInitializer: String,
    private val requireSyntheticDefinition: () -> Unit,
) {
    fun placeholderDefinition(): String {
        requireSyntheticDefinition()
        return "$prototype {\n${placeholderBody()}\n}"
    }

    fun placeholderBody(): String {
        require(!noReturn) { "unsupported generated-C placeholder for $entityId: _Noreturn requires a retained non-returning implementation" }
        require(!hasInlineSpecifier || hasInternalLinkage) {
            "unsupported generated-C placeholder for $entityId: an external inline definition requires retained linkage evidence"
        }
        require(!hasUnnamedParameters) { "unsupported generated-C placeholder for $entityId: parameter names are unavailable" }
        val used = unusedParameterReferences(parameterNames)
        if (returnKind == GeneratedCTypeKind.VOID) return used + "    return;"
        // A declaration, rather than a guessed cast to int, also supports pointers, structs,
        // and explicitly declared typedefs. The compiler still decides whether the type is valid.
        val identifiers = cDeclarationTokens(prototype).mapTo(hashSetOf()) { it.text }
        val name = generateSequence("decomp_placeholder_result") { "${it}_" }.first { it !in identifiers }
        return used + "    ${resultDeclaration(name)} = $zeroInitializer;\n    return $name;"
    }

    fun entryCall(name: String): String {
        require(explicitNoParameters) { "unsupported generated-C entry call for $entityId: an explicit void parameter list is required" }
        requireExternalDeclaration("synthesized entry module")
        require(returnKind == GeneratedCTypeKind.VOID || returnKind == GeneratedCTypeKind.INTEGER) {
            "unsupported generated-C entry call for $entityId: the recovered return type has no supported integer process-status contract"
        }
        return if (returnKind == GeneratedCTypeKind.VOID) "$name();\n    return 0;" else "return $name();"
    }

    fun requireExternalDeclaration(boundary: String) {
        require(!hasInternalLinkage && !hasInlineSpecifier) {
            "unsupported generated-C module boundary for $entityId: static or inline declarations require a definition in $boundary"
        }
    }
}

internal fun recoveredDeclaration(
    function: RecoveredFunction,
    context: GeneratedCDeclarationContext = GeneratedCDeclarationContext.EMPTY,
): GeneratedCFunctionDeclaration = declarationFor(function.id) {
    val declaration = CDeclarationParser(function.prototype.trim(), function.name).parse()
    require("typedef" !in declaration.specifiers) { "prototype declares a typedef, not a function" }
    require(declaration.name?.text == function.name) { "prototype must declare ${function.name}" }
    val parameters = declaration.derived.firstOrNull() as? CDerived.Function
        ?: error("prototype must declare a function, not a pointer or object")
    val identifier = requireNotNull(declaration.name)
    val source = declaration.source
    val prototype = source.replaceRange(identifier.start, identifier.end, safeCName(function.name))
    val soleVoidParameter = parameters.explicitVoid || (parameters.parameters.singleOrNull()?.let {
        it.name == null && context.classify(it.specifiers, it.derived, it.atomicType) == GeneratedCTypeKind.VOID
    } == true)
    GeneratedCFunctionDeclaration(
        entityId = function.id,
        prototype = prototype,
        parameterNames = parameters.parameters.mapNotNull { it.name?.text },
        hasUnnamedParameters = !soleVoidParameter && parameters.parameters.any { it.name == null },
        explicitNoParameters = soleVoidParameter,
        hasInternalLinkage = "static" in declaration.specifiers,
        hasInlineSpecifier = "inline" in declaration.specifiers,
        hasExternSpecifier = "extern" in declaration.specifiers,
        noReturn = "_Noreturn" in declaration.specifiers,
        returnKind = context.classify(declaration.specifiers, declaration.derived.drop(1), declaration.atomicType),
        zeroInitializer = context.zeroInitializer(declaration.specifiers, declaration.derived.drop(1), declaration.atomicType),
        requireSyntheticDefinition = {
            require(context.supportsZeroInitializer(declaration.specifiers, declaration.derived.drop(1), declaration.atomicType)) {
                "unsupported generated-C placeholder for ${function.id}: atomic aggregate zero initialization requires retained implementation evidence"
            }
            // Nested callback/returned-function parameter lists remain prototype scope. Only
            // the actual definition's parameter object declarators lose that scope here.
            require(parameters.parameters.none { parameter ->
                parameter.derived.takeWhile { it !is CDerived.Function }.any { it is CDerived.Array && it.prototypeOnlyStar }
            }) {
                "unsupported generated-C placeholder for ${function.id}: prototype-only [*] parameters require a retained definition; adjusting the bound conflicts with strict compiler declaration checks"
            }
        },
        resultDeclaration = { name ->
            // Removing only the outer function suffix preserves even a pointer-to-function return.
            val edits = declaration.storageSpecifiers.map { Triple(it.start, it.end, "") } +
                listOf(Triple(parameters.start, parameters.end, ""), Triple(identifier.start, identifier.end, name))
            edits.sortedByDescending { it.first }.fold(source) { text, (start, end, replacement) ->
                text.replaceRange(start, end, replacement)
            }.trimStart()
        },
    )
}

internal fun globalDeclaration(
    global: RecoveredGlobal,
    external: Boolean,
    context: GeneratedCDeclarationContext = GeneratedCDeclarationContext.EMPTY,
): String = declarationFor(global.id) {
    val type = CDeclarationParser(global.type.trim()).parse(allowAbstract = true)
    require(type.name == null) { "global type must be an abstract declarator without an object name" }
    val kind = context.classify(type.specifiers, type.derived, type.atomicType)
    val retained = global.initializer?.takeUnless(String::isBlank)
    require(kind != GeneratedCTypeKind.FUNCTION) { "global type denotes a function, not an object" }
    require(external || retained != null || kind != GeneratedCTypeKind.INCOMPLETE_ARRAY) {
        "an unsized array requires retained initializer evidence; a zero placeholder would invent its extent"
    }
    val declaration = type.source.substring(0, type.nameOffset).trimEnd() + " " + safeCName(global.name) +
        type.source.substring(type.nameOffset)
    if (external) "extern $declaration;"
    else {
        // Null or blank text supplies no initializer evidence. Nonblank expressions are
        // compiler checked; an unfamiliar value must not silently become zero.
        val initializer = retained?.let(::retainedInitializer) ?: run {
            require(context.supportsZeroInitializer(type.specifiers, type.derived, type.atomicType)) {
                "atomic aggregate zero initialization requires retained initializer evidence"
            }
            context.zeroInitializer(type.specifiers, type.derived, type.atomicType)
        }
        "$declaration = $initializer;"
    }
}

internal enum class GeneratedCTypeKind { VOID, INTEGER, POINTER, ARRAY, INCOMPLETE_ARRAY, FUNCTION, OTHER, UNKNOWN }

/** Resolves only declaration shapes needed by generated code; the compiler still validates C types. */
internal class GeneratedCDeclarationContext(types: List<RecoveredType>) {
    private val aliases = linkedMapOf<String, CDeclaration>()
    private data class ResolvedType(
        val kind: GeneratedCTypeKind,
        val resolutionDepth: Int = 0,
        val atomic: Boolean = false,
        val scalar: Boolean = false,
        val unsupportedZeroInitializer: Boolean = false,
    )
    private val resolved = hashMapOf<String, ResolvedType>()

    init {
        var characters = 0L
        for (type in types) declarationFor(type.id) {
            characters += type.declaration.length.toLong()
            require(type.declaration.length <= 1024 * 1024 && characters <= 64L * 1024 * 1024) {
                "typedef context exceeds its source bounds"
            }
            require(generatedCAttributionPreprocessorIssue(type.declaration, allowIncludes = false) == null &&
                cDeclarationTokens(type.declaration).none { it.text == "#" }) {
                "preprocessor-dependent type declarations cannot establish a typedef shape"
            }
            for (statement in splitCTypeSource(type.declaration, ";")) {
                if (cDeclarationTokens(statement).none { it.text == "typedef" }) continue
                // Aggregate member declarations do not affect the outer alias's object shape.
                // This is a parsing view only: published type declarations retain the original bytes.
                val parts = splitCTypeSource(aliasParsingView(statement), ",")
                val first = CDeclarationParser(parts.first()).parse()
                val prefix = first.source.substring(0, first.declaratorOffset)
                val declarations = listOf(first) + parts.drop(1).map { CDeclarationParser(prefix + it).parse() }
                for (declaration in declarations) {
                    require("typedef" in declaration.specifiers) { "alias is missing its typedef specifier" }
                    val name = requireNotNull(declaration.name) { "typedef has no alias name" }.text
                    val previous = aliases[name]
                    require(previous == null || cDeclarationTokens(previous.source).map { it.text } ==
                        cDeclarationTokens(declaration.source).map { it.text }) {
                        "conflicting or unsupported repeated typedef $name"
                    }
                    if (previous == null) {
                        require(aliases.size < 131_072) { "typedef inventory exceeds its bound" }
                        aliases[name] = declaration
                    }
                }
            }
        }
    }

    @Synchronized
    internal fun classify(
        specifiers: List<String>,
        derived: List<CDerived>,
        atomicType: CDeclaration? = null,
    ): GeneratedCTypeKind = resolve(specifiers, derived, atomicType, linkedSetOf(), 0).kind

    @Synchronized
    internal fun zeroInitializer(specifiers: List<String>, derived: List<CDerived>, atomicType: CDeclaration? = null): String {
        val type = resolve(specifiers, derived, atomicType, linkedSetOf(), 0)
        return if (type.atomic && type.scalar) "0" else "{0}"
    }

    /** Emission-only policy: header rendering and typed-placeholder recognition must remain usable. */
    @Synchronized
    internal fun supportsZeroInitializer(specifiers: List<String>, derived: List<CDerived>, atomicType: CDeclaration? = null): Boolean =
        !resolve(specifiers, derived, atomicType, linkedSetOf(), 0).unsupportedZeroInitializer

    private fun resolve(
        specifiers: List<String>,
        derived: List<CDerived>,
        atomicType: CDeclaration?,
        visiting: MutableSet<String>,
        depth: Int,
    ): ResolvedType {
        // Use-site operators precede alias operators: an A* stays a pointer even if A is int[].
        when (val outer = derived.firstOrNull()) {
            is CDerived.Pointer -> return ResolvedType(GeneratedCTypeKind.POINTER, atomic = outer.atomic, scalar = true)
            is CDerived.Array -> {
                // Skip consecutive dimensions iteratively; aliases still use the bounded resolver.
                val element = resolve(specifiers, derived.dropWhile { it is CDerived.Array }, atomicType, visiting, depth)
                return ResolvedType(if (outer.hasBound) GeneratedCTypeKind.ARRAY else GeneratedCTypeKind.INCOMPLETE_ARRAY,
                    resolutionDepth = element.resolutionDepth, unsupportedZeroInitializer = element.unsupportedZeroInitializer)
            }
            is CDerived.Function -> return ResolvedType(GeneratedCTypeKind.FUNCTION)
            null -> Unit
        }
        val base = specifiers.filterNot { it in cStorageSpecifiers || it in setOf("const", "volatile", "restrict", "_Atomic") }
        if (atomicType != null) {
            // The complete atomic specifier is one base type; any additional base type is
            // invalid C and must not acquire the shape of just one of its specifiers.
            if (base.size != 1) return ResolvedType(GeneratedCTypeKind.UNKNOWN)
            require(depth < 64) { "typedef or atomic type resolution exceeds depth 64" }
            val inner = resolve(atomicType.specifiers, atomicType.derived, atomicType.atomicType, visiting, depth + 1)
            // Invalid atomic void must not be interpreted as an explicit no-parameter list.
            // Keep array shape information to avoid inventing an alias-hidden array extent.
            val kind = if (inner.kind == GeneratedCTypeKind.VOID) GeneratedCTypeKind.OTHER else inner.kind
            return inner.copy(kind = kind, resolutionDepth = inner.resolutionDepth + 1, atomic = true,
                unsupportedZeroInitializer = !inner.scalar || inner.unsupportedZeroInitializer)
        }
        if (base == listOf("void")) return ResolvedType(GeneratedCTypeKind.VOID).withAtomicQualifier(specifiers)
        if (base.isNotEmpty() && base.all { it in integerSpecifiers }) {
            return ResolvedType(GeneratedCTypeKind.INTEGER, scalar = true).withAtomicQualifier(specifiers)
        }
        if (base.firstOrNull() == "enum") return ResolvedType(GeneratedCTypeKind.INTEGER, scalar = true).withAtomicQualifier(specifiers)
        if (base.firstOrNull() in setOf("struct", "union")) return ResolvedType(GeneratedCTypeKind.OTHER).withAtomicQualifier(specifiers)
        if (base.any { it in setOf("float", "double", "_Complex") }) {
            return ResolvedType(GeneratedCTypeKind.OTHER, scalar = true).withAtomicQualifier(specifiers)
        }
        val name = base.singleOrNull() ?: return ResolvedType(GeneratedCTypeKind.UNKNOWN)
        val alias = aliases[name] ?: return ResolvedType(
            if (name in standardIntegerAliases) GeneratedCTypeKind.INTEGER else GeneratedCTypeKind.UNKNOWN,
            scalar = name in standardIntegerAliases,
        ).withAtomicQualifier(specifiers)
        resolved[name]?.let {
            require(depth + it.resolutionDepth <= 64) { "typedef resolution exceeds depth 64 at $name" }
            return it.withAtomicQualifier(specifiers)
        }
        require(depth < 64 && visiting.add(name)) { "cyclic typedef or typedef resolution exceeds depth 64 at $name" }
        val result = resolve(alias.specifiers, alias.derived, alias.atomicType, visiting, depth + 1)
            .let { it.copy(resolutionDepth = it.resolutionDepth + 1) }
        visiting.remove(name)
        resolved[name] = result
        return result.withAtomicQualifier(specifiers)
    }

    // A use-site qualifier changes this result, never the cached unqualified alias shape.
    private fun ResolvedType.withAtomicQualifier(specifiers: List<String>): ResolvedType =
        if ("_Atomic" in specifiers) copy(kind = if (kind == GeneratedCTypeKind.VOID) GeneratedCTypeKind.OTHER else kind,
            atomic = true, unsupportedZeroInitializer = !scalar || unsupportedZeroInitializer) else this

    companion object {
        val EMPTY = GeneratedCDeclarationContext(emptyList())
        private val integerSpecifiers = setOf("char", "short", "int", "long", "signed", "unsigned", "_Bool")
        // These typedefs come from the standard headers emitted by sharedInterface; no widths are guessed.
        private val standardIntegerAliases = setOf("size_t", "ptrdiff_t", "wchar_t", "intptr_t", "uintptr_t", "intmax_t", "uintmax_t") +
            listOf(8, 16, 32, 64).flatMap { bits -> listOf("int${bits}_t", "uint${bits}_t", "int_least${bits}_t", "uint_least${bits}_t", "int_fast${bits}_t", "uint_fast${bits}_t") }
    }
}

/** One immutable context per currently processed type inventory, avoiding a scan per function. */
internal class GeneratedCDeclarationContextCache {
    private var previousTypes: List<RecoveredType>? = null
    private var previousContext: GeneratedCDeclarationContext? = null

    @Synchronized
    fun forTypes(types: List<RecoveredType>): GeneratedCDeclarationContext {
        if (previousTypes == types) return requireNotNull(previousContext)
        val snapshot = types.toList()
        return GeneratedCDeclarationContext(snapshot).also { previousTypes = snapshot; previousContext = it }
    }
}

/**
 * Select whole recovered declarations by their named dependencies. Names inside comments and
 * literals are not evidence. Tag names use C's separate namespace; ordinary names are a
 * conservative lexical dependency because recovered bodies need not be parseable C yet.
 * A recovered record can contain several declarations and remains an indivisible evidence unit.
 */
private data class CTypeExport(val type: RecoveredType, val signature: List<String>, val definition: Boolean, val enumerator: Boolean)
private data class CTypeIndex(val exports: Map<String, List<CTypeExport>>, val references: Map<String, Set<String>>)

private val cTypeIdentifier = Regex("[A-Za-z_][A-Za-z0-9_]*")

private fun cTypeNames(tokens: List<CToken>, work: COrderWork? = null): Set<String> = buildSet {
    tokens.forEachIndexed { index, token ->
        work?.step()
        if (token.text.matches(cTypeIdentifier) && token.text !in setOf("struct", "union", "enum")) {
            add(if (tokens.getOrNull(index - 1)?.text in setOf("struct", "union", "enum")) "tag:${token.text}" else "name:${token.text}")
        }
    }
}

private fun cTypeIndex(types: List<RecoveredType>, work: COrderWork? = null): CTypeIndex {
    val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
    val aggregateKeywords = setOf("struct", "union", "enum")
    val exports = linkedMapOf<String, MutableList<CTypeExport>>()
    val references = linkedMapOf<String, Set<String>>()
    var characters = 0L
    var exportCount = 0

    fun export(key: String, type: RecoveredType, signature: List<String>, definition: Boolean = true, enumerator: Boolean = false) {
        work?.step()
        require(++exportCount <= 131_072) { "recovered type dependency inventory exceeds its bound" }
        exports.getOrPut(key) { mutableListOf() } += CTypeExport(type, signature, definition, enumerator)
    }

    for (type in types.sortedWith { left, right -> work?.step(); left.id.compareTo(right.id) }) declarationFor(type.id) {
        work?.span(type.declaration.length)
        characters += type.declaration.length.toLong()
        require(type.declaration.length <= 1024 * 1024 && characters <= 64L * 1024 * 1024) {
            "recovered type dependency context exceeds its source bounds"
        }
        require(generatedCAttributionPreprocessorIssue(type.declaration, allowIncludes = false) == null) {
            "preprocessor-dependent type declarations cannot establish dependencies"
        }
        val tokens = cDeclarationTokens(type.declaration, work = work)
        require(tokens.none { work?.step(); it.text == "#" }) { "preprocessor-dependent type declarations cannot establish dependencies" }
        references[type.id] = cTypeNames(tokens, work)
        for (statement in splitCTypeSource(type.declaration, ";", work)) {
            val statementTokens = cDeclarationTokens(statement, work = work)
            val scope = cTypeDeclarationScope(statement, work)
            scope.introductions.forEach { (kind, tag) ->
                export("tag:$tag", type, listOf(kind, tag), definition = false)
            }
            if (statementTokens.any { work?.step(); it.text == "typedef" }) {
                val parsingView = aliasParsingSourceView(statement, work = work)
                val parts = splitCTypeSourceParts(parsingView.source, ",", work)
                val first = CDeclarationParser(parts.first().source, work = work).parse()
                // Preserve previously admitted bodyless enum typedef introductions. The
                // strict compiler, not this additional scope inventory, owns their validity.
                if (parsingView.source == statement) first.specifiers.zipWithNext().firstOrNull { (kind, tag) ->
                    kind == "enum" && tag.matches(identifier)
                }?.let { (kind, tag) -> export("tag:$tag", type, listOf(kind, tag), definition = false) }
                val prefix = first.source.cOrderSlice(0, first.declaratorOffset, work = work)
                val originalPrefix = statement.cOrderSlice(0, parsingView.originalOffset(first.declaratorOffset), work = work)
                for ((index, part) in parts.withIndex()) {
                    work?.span(prefix.length + part.source.length)
                    val declaration = if (index == 0) first else CDeclarationParser(prefix + part.source, work = work).parse()
                    val name = requireNotNull(declaration.name) { "typedef has no alias name" }.text
                    // Identity belongs to this alias, not its sibling declarators. Restore
                    // original aggregate bodies rather than comparing synthetic parsing tags.
                    // Selection still retains the entire recovered record as evidence.
                    val originalPart = statement.cOrderSlice(parsingView.originalOffset(part.start),
                        parsingView.originalOffset(part.start + part.source.length), work = work)
                    work?.span(originalPrefix.length + originalPart.length)
                    val aliasSource = if (index == 0) originalPart else originalPrefix + originalPart
                    export("name:$name", type, cDeclarationTokens(aliasSource, work = work).map { work?.step(); it.text })
                }
            }
            statementTokens.forEachIndexed { index, token ->
                work?.step()
                if (token.text !in aggregateKeywords) return@forEachIndexed
                if (scope.isPrototypeOffset(token.start)) return@forEachIndexed
                val tag = statementTokens.getOrNull(index + 1)?.takeIf { it.text.matches(identifier) }
                val body = index + if (tag == null) 1 else 2
                if (statementTokens.getOrNull(body)?.text == "{") {
                    val end = matchingCTypeBody(statementTokens, body, work)
                    val signature = statementTokens.subList(index, end + 1).map { work?.step(); it.text }
                    if (tag != null) export("tag:${tag.text}", type, signature)
                    if (token.text == "enum") {
                        val bodyText = statement.cOrderSlice(statementTokens[body].end, statementTokens[end].start, work = work)
                        for (entry in splitCTypeSource(bodyText, ",", work)) {
                            val enumerator = cDeclarationTokens(entry, work = work).firstOrNull()
                            require(enumerator?.text?.matches(identifier) == true) { "enum member lacks an identifier" }
                            export("name:${enumerator.text}", type, signature, enumerator = true)
                        }
                    }
                } else if (tag != null && index == 0 && body == statementTokens.size && token.text == "enum") {
                    export("tag:${tag.text}", type, statementTokens.map { work?.step(); it.text }, definition = false)
                }
            }
        }
    }

    return CTypeIndex(exports.mapValues { it.value.toList() }, references.toMap())
}

internal fun selectRequiredGeneratedCTypes(types: List<RecoveredType>, evidence: List<String>): List<RecoveredType> {
    val (exports, references) = cTypeIndex(types)
    val pending = ArrayDeque<String>()
    var evidenceCharacters = 0L
    evidence.forEach { source ->
        evidenceCharacters += source.length.toLong()
        require(evidenceCharacters <= 64L * 1024 * 1024) { "recovered type dependency evidence exceeds its source bound" }
        cTypeNames(cDeclarationTokens(source)).sorted().forEach(pending::addLast)
    }
    val visited = hashSetOf<String>()
    val selected = linkedMapOf<String, RecoveredType>()
    while (pending.isNotEmpty()) {
        val name = pending.removeFirst()
        if (!visited.add(name)) continue
        val candidates = exports[name].orEmpty()
        if (candidates.isEmpty()) continue // Built-in, standard-header, or unrecovered names remain explicit source evidence.
        val definitions = candidates.filter { it.definition }.ifEmpty { candidates }
        require(definitions.map { it.signature }.distinct().size == 1) {
            "ambiguous recovered type dependency $name in ${definitions.map { it.type.id }.distinct().sorted()}"
        }
        val chosen = definitions.minBy { it.type.id }
        val preceding = candidates.asSequence()
            .filter { !it.definition && it.type.id < chosen.type.id &&
                it.signature == chosen.signature.take(2) }
            .minByOrNull { it.type.id }
        for (required in listOfNotNull(preceding, chosen)) {
            val type = required.type
            if (selected.putIfAbsent(type.id, type) == null) references.getValue(type.id).sorted().forEach(pending::addLast)
        }
    }
    return selected.values.sortedBy { it.id }
}

/** Aggregate members inherit their containing scope; every parameter list has its own child scope. */
private data class CTypePrototypeScope(val id: Int, val parent: Int?, val start: Int, val end: Int)
private data class CTypeDeclarationScope(
    val introductions: List<Pair<String, String>>,
    val prototypeRanges: List<IntRange>,
    val parameterScopes: List<CTypePrototypeScope>,
    private val work: COrderWork? = null,
) {
    fun isPrototypeOffset(offset: Int): Boolean {
        var low = 0
        var high = prototypeRanges.size
        while (low < high) {
            work?.step()
            val middle = (low + high) ushr 1
            if (prototypeRanges[middle].first <= offset) low = middle + 1 else high = middle
        }
        return low > 0 && offset <= prototypeRanges[low - 1].last
    }
}

private fun cTypeDeclarationScope(source: String, work: COrderWork? = null): CTypeDeclarationScope {
    val introductions = linkedSetOf<Pair<String, String>>()
    val prototypes = java.util.TreeMap<Int, Int>()
    val parameterScopes = mutableListOf<CTypePrototypeScope>()
    val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")

    fun inPrototype(offset: Int): Boolean = prototypes.floorEntry(offset)?.value?.let { offset < it } == true
    fun addPrototype(start: Int, end: Int) {
        if (prototypes.floorEntry(start)?.value?.let { it >= end } == true) return
        require(prototypes.floorEntry(start)?.value?.let { it > start } != true) { "overlapping type prototype scopes" }
        while (prototypes.ceilingEntry(start)?.key?.let { it < end } == true) {
            work?.step()
            val nested = prototypes.ceilingEntry(start)
            require(nested.value <= end) { "overlapping type prototype scopes" }
            prototypes.remove(nested.key)
        }
        prototypes[start] = end
    }

    fun functionScopes(declaration: CDeclaration, original: (Int) -> Int, parent: Int? = null, depth: Int = 0) {
        work?.step()
        require(depth < 64) { "declarator nesting exceeds 64" }
        for (function in declaration.derived) {
            work?.step()
            if (function !is CDerived.Function) continue
            val id = parameterScopes.size
            val start = original(function.start)
            val end = original(function.end)
            parameterScopes += CTypePrototypeScope(id, parent, start, end)
            // The selector consumes the historical merged view, derived from the same tree.
            addPrototype(start, end)
            for ((index, parameter) in function.parameters.withIndex()) {
                val offset = function.parameterStarts[index]
                functionScopes(parameter, { original(offset + it) }, id, depth + 1)
            }
        }
        declaration.atomicType?.let { atomic ->
            val tokens = cDeclarationTokens(declaration.source, work = work)
            val start = tokens.indices.first { index ->
                work?.step()
                tokens[index].start < declaration.declaratorOffset && tokens[index].text == "_Atomic" &&
                    tokens.getOrNull(index + 1)?.text == "("
            }
            functionScopes(atomic, { original(tokens[start + 1].end + it) }, parent, depth + 1)
        }
    }

    fun visit(declaration: String, originalStart: Int, depth: Int) {
        require(depth <= 64) { "recovered type aggregate nesting exceeds 64" }
        val tokens = cDeclarationTokens(declaration, work = work)
        if (tokens.none { it.text in setOf("struct", "union", "enum") }) return
        val view = aliasParsingSourceView(declaration, omitAlignmentSpecifiers = true, work = work)
        val parts = splitCTypeSourceParts(view.source, ",", work)
        // Non-typedef recovered records were never required to fit the declarator parser.
        // Keep their existing export handling when this additional analysis is unavailable.
        val parsed = if (parts.isEmpty()) null else try {
            val first = CDeclarationParser(cTypeBeforeInitializer(parts.first().source, work), work = work).parse(allowAbstract = true)
            val prefix = first.source.cOrderSlice(0, first.declaratorOffset, work = work)
            val declarations = listOf(first to { offset: Int -> offset }) + parts.drop(1).map { part ->
                CDeclarationParser(prefix + cTypeBeforeInitializer(part.source, work), work = work).parse(allowAbstract = true) to
                    { offset: Int -> if (offset < prefix.length) offset else part.start + offset - prefix.length }
            }
            first to declarations
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: IllegalStateException) {
            null
        }
        parsed?.second?.forEach { (item, offset) ->
            val parent = parameterScopes.lastOrNull { originalStart > it.start && originalStart < it.end }?.id
            functionScopes(item, { originalStart + view.originalOffset(offset(it)) }, parent)
        }
        // A member's leading type specifiers have the surrounding scope even when its
        // declarator uses an extension that the optional parser above does not support.
        // Do not walk arbitrary parentheses or bodies after the declarator has started.
        var index = 0
        var hasType = false
        while (index < tokens.size) {
            work?.step()
            val token = tokens[index]
            when {
                token.text in setOf("_Alignas", "_Atomic") && tokens.getOrNull(index + 1)?.text == "(" -> {
                    val end = matchingCToken(tokens, index + 1, work)
                    val innerStart = tokens[index + 1].end
                    val inner = declaration.cOrderSlice(innerStart, tokens[end].start, work = work)
                    val first = cDeclarationTokens(inner, work = work).firstOrNull()?.text
                    if (token.text == "_Atomic" || first in setOf("struct", "union", "enum", "_Atomic", "const", "volatile",
                            "restrict", "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex")) {
                        visit(inner, originalStart + innerStart, depth + 1)
                    }
                    if (token.text == "_Atomic") hasType = true
                    index = end + 1
                }
                token.text in setOf("struct", "union", "enum") -> {
                    val tag = tokens.getOrNull(index + 1)?.takeIf { it.text.matches(identifier) }
                    val body = index + if (tag == null) 1 else 2
                    if (tokens.getOrNull(body)?.text == "{") {
                        val end = matchingCTypeBody(tokens, body, work)
                        if (token.text != "enum" && !inPrototype(originalStart + token.start)) {
                            val memberStart = tokens[body].end
                            val members = declaration.cOrderSlice(memberStart, tokens[end].start, work = work)
                            splitCTypeSourceParts(members, ";", work).forEach { member ->
                                visit(member.source, originalStart + memberStart + member.start, depth + 1)
                            }
                        }
                        index = end + 1
                    } else {
                        if (tag == null) return
                        if (token.text != "enum" && !inPrototype(originalStart + token.start)) {
                            introductions += token.text to tag.text
                        }
                        index = body
                    }
                    hasType = true
                }
                token.text in cStorageSpecifiers || token.text in setOf("const", "volatile", "restrict", "_Atomic") -> index++
                token.text in setOf("void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex") -> {
                    hasType = true
                    index++
                }
                !hasType && token.text.matches(identifier) -> { hasType = true; index++ }
                else -> break
            }
        }
    }
    visit(source, 0, 0)
    return CTypeDeclarationScope(introductions.toList(), prototypes.map { (start, end) -> start until end }, parameterScopes.toList(), work)
}

private fun cTypeBeforeInitializer(source: String, work: COrderWork? = null): String {
    var depth = 0
    for (token in cDeclarationTokens(source, work = work)) when (token.text) {
        "(", "[", "{" -> depth++
        ")", "]", "}" -> depth--
        "=" -> if (depth == 0) return source.cOrderSlice(0, token.start, work = work)
    }
    return source
}

private fun matchingCTypeBody(tokens: List<CToken>, start: Int, work: COrderWork? = null): Int {
    var depth = 0
    for (index in start until tokens.size) {
        work?.step()
        when (tokens[index].text) {
        "{" -> { require(++depth <= 64) { "recovered type aggregate nesting exceeds 64" } }
        "}" -> if (--depth == 0) return index
        }
    }
    error("unclosed recovered type aggregate")
}

private data class CTypeSourcePart(val source: String, val start: Int)

private fun splitCTypeSource(source: String, separator: String, work: COrderWork? = null): List<String> =
    splitCTypeSourceParts(source, separator, work).map { it.source }

private fun splitCTypeSourceParts(source: String, separator: String, work: COrderWork? = null): List<CTypeSourcePart> {
    work?.span(source.length)
    val tokens = cDeclarationTokens(source, work = work)
    val stack = mutableListOf<String>()
    val parts = mutableListOf<CTypeSourcePart>()
    var start = 0
    for (token in tokens) {
        work?.step()
        when (token.text) {
            "(", "[", "{" -> {
                require(stack.size < 64) { "typedef declarator nesting exceeds 64" }
                stack += token.text
            }
            ")", "]", "}" -> {
                val expected = when (token.text) { ")" -> "("; "]" -> "["; else -> "{" }
                require(stack.isNotEmpty() && stack.removeAt(stack.lastIndex) == expected) { "unbalanced type declaration" }
            }
            separator -> if (stack.isEmpty()) {
                parts += CTypeSourcePart(source.cOrderSlice(start, token.start, work = work), start)
                start = token.end
            }
        }
    }
    require(stack.isEmpty()) { "unclosed type declaration" }
    val tail = source.cOrderSlice(start, work = work)
    if (cDeclarationTokens(tail, work = work).isNotEmpty()) parts += CTypeSourcePart(tail, start)
    return parts.filter { cDeclarationTokens(it.source, work = work).isNotEmpty() }
}

private data class CTypeSourceReplacement(val originalEnd: Int, val viewStart: Int, val viewEnd: Int, val originalStart: Int)

private data class CTypeAliasSourceView(val source: String, val replacements: List<CTypeSourceReplacement>, private val work: COrderWork? = null) {
    fun originalOffset(offset: Int): Int {
        var low = 0
        var high = replacements.size
        while (low < high) {
            work?.step()
            val middle = (low + high) ushr 1
            if (replacements[middle].viewEnd <= offset) low = middle + 1 else high = middle
        }
        require(low == replacements.size || offset <= replacements[low].viewStart) {
            "type scope offset lies inside a replaced aggregate body"
        }
        return if (low == 0) offset else offset + replacements[low - 1].originalEnd - replacements[low - 1].viewEnd
    }
}

private fun aliasParsingView(source: String): String = aliasParsingSourceView(source).source

private fun aliasParsingSourceView(source: String, omitAlignmentSpecifiers: Boolean = false, work: COrderWork? = null): CTypeAliasSourceView {
    work?.span(source.length)
    val tokens = cDeclarationTokens(source, work = work)
    val edits = mutableListOf<Triple<Int, Int, String>>()
    var index = 0
    while (index < tokens.size) {
            work?.step()
        if (omitAlignmentSpecifiers && tokens[index].text == "_Alignas" && tokens.getOrNull(index + 1)?.text == "(") {
            val end = matchingCToken(tokens, index + 1, work)
            edits += Triple(tokens[index].start, tokens[end].end, "")
            index = end + 1
            continue
        }
        if (tokens[index].text in setOf("struct", "union", "enum")) {
            val aggregateStart = index
            var body = index + 1
            if (tokens.getOrNull(body)?.text != "{") body++
            if (tokens.getOrNull(body)?.text == "{") {
                var nesting = 1
                var end = body + 1
                while (end < tokens.size && nesting > 0) {
                    work?.step()
                    require(nesting <= 64) { "recovered type aggregate nesting exceeds 64" }
                    if (tokens[end].text == "{") nesting++
                    if (tokens[end].text == "}") nesting--
                    end++
                }
                require(nesting == 0) { "unclosed typedef aggregate body" }
                edits += Triple(tokens[aggregateStart].start, tokens[end - 1].end, "${tokens[aggregateStart].text} decomp_context_tag")
                index = end
                continue
            }
        }
        index++
    }
    val replacements = mutableListOf<CTypeSourceReplacement>()
    val view = buildString {
        var previous = 0
        edits.forEach { (start, end, replacement) ->
            append(source, previous, start)
            val viewStart = length
            append(replacement)
            replacements += CTypeSourceReplacement(end, viewStart, length, start)
            previous = end
        }
        append(source, previous, source.length)
    }
    return CTypeAliasSourceView(view, replacements, work)
}

private fun retainedInitializer(raw: String): String {
    var trailingLineComment = false
    val tokens = cDeclarationTokens(raw) { trailingLineComment = true }
    require(tokens.isNotEmpty()) { "empty global initializer" }
    val stack = mutableListOf<String>()
    for (token in tokens) {
        when (token.text) {
            "(", "[", "{" -> stack += token.text
            ")", "]", "}" -> {
                val expected = when (token.text) { ")" -> "("; "]" -> "["; else -> "{" }
                require(stack.isNotEmpty() && stack.removeAt(stack.lastIndex) == expected) { "unbalanced global initializer" }
            }
            ";", "#" -> error("unsupported token in global initializer: ${token.text}")
            "," -> require(stack.isNotEmpty()) { "global initializer contains multiple declarators" }
        }
    }
    require(stack.isEmpty()) { "unclosed global initializer" }
    val value = if (tokens.size == 1 && tokens.single().text.matches(Regex("[0-9a-fA-F]+h"))) {
        val token = tokens.single()
        raw.replaceRange(token.start, token.end, "0x${token.text.dropLast(1)}")
    } else raw
    return value + if (trailingLineComment) "\n" else ""
}

/** Parameter reads for a recovered definition use its own declarators, never a comma/name regex. */
internal fun markRecoveredParametersUsed(source: String, function: RecoveredFunction): String = declarationFor(function.id) {
    val definition = findCFunctionDefinition(source, setOf(function.name, safeCName(function.name))) ?: return@declarationFor source
    val parameters = definition.declaration.derived.first() as CDerived.Function
    val uses = unusedParameterReferences(parameters.parameters.mapNotNull { it.name?.text }.distinct())
    source.substring(0, definition.bodyStart) + "\n" + uses + source.substring(definition.bodyStart)
}

/** Supports full declarators (including function-pointer returns) in candidate body checks. */
internal fun generatedCFunctionBody(source: String, name: String): String? = runCatching {
    if (generatedCAttributionPreprocessorIssue(source) != null) return@runCatching null
    findCFunctionDefinition(source, setOf(name))?.let { source.substring(it.bodyStart, it.bodyEnd) }
}.getOrNull()

/** Match typed zero-return stubs independently of their local result names. */
internal fun isGeneratedCPlaceholderBody(
    function: RecoveredFunction,
    body: String,
    context: GeneratedCDeclarationContext = GeneratedCDeclarationContext.EMPTY,
): Boolean = runCatching {
    val expected = normalizedPlaceholderBody(recoveredDeclaration(function, context).placeholderBody())
    expected != null && normalizedPlaceholderBody(body) == expected
}.getOrDefault(false)

/** Match the legacy simple return stubs without treating control-flow semicolons as no-ops. */
internal fun isGeneratedCSimpleReturnBody(body: String): Boolean = runCatching {
    val tokens = cDeclarationTokens(body)
    val start = placeholderBodyStart(tokens) ?: return@runCatching false
    if (tokens.getOrNull(start)?.text != "return") return@runCatching false
    val end = if (tokens.getOrNull(start + 1)?.text == ";") start + 1
        else zeroExpressionEnd(tokens, start + 1) ?: return@runCatching false
    tokens.getOrNull(end)?.text == ";" && skipEmptyCStatements(tokens, end + 1) == tokens.size
}.getOrDefault(false)

private fun normalizedPlaceholderBody(body: String): List<String>? {
    val tokens = cDeclarationTokens(body)
    val start = placeholderBodyStart(tokens) ?: return null
    if (hasCTokens(tokens, start, listOf("return", ";")) &&
        skipEmptyCStatements(tokens, start + 2) == tokens.size) return listOf("return", ";")
    var initializer = start
    while (initializer < tokens.size && tokens[initializer].text != "=") {
        when (tokens[initializer].text) {
            "(", "[" -> initializer = matchingCToken(tokens, initializer)
            ";", "{", "}" -> return null
        }
        initializer++
    }
    if (initializer == start || initializer >= tokens.size) return null
    val declaration = CDeclarationParser(body.substring(tokens[start].start, tokens[initializer].start)).parse()
    val name = declaration.name ?: return null
    val initializerEnd = zeroInitializerEnd(tokens, initializer + 1) ?: return null
    if (tokens.getOrNull(initializerEnd)?.text != ";") return null
    val returnStart = skipEmptyCStatements(tokens, initializerEnd + 1)
    if (tokens.getOrNull(returnStart)?.text != "return") return null
    val returnEnd = parenthesizedIdentifierEnd(tokens, returnStart + 1, name.text) ?: return null
    if (tokens.getOrNull(returnEnd)?.text != ";" || skipEmptyCStatements(tokens, returnEnd + 1) != tokens.size) return null
    // Replace only the declared identifier: the same spelling may also be a struct tag,
    // typedef name, or a parameter inside a function-pointer declarator.
    return cDeclarationTokens(declaration.source).map {
        if (it.start == name.start && it.end == name.end) "<result>" else it.text
    }
}

private fun placeholderBodyStart(tokens: List<CToken>): Int? {
    var start = skipEmptyCStatements(tokens, 0)
    // The generated dead branch has no runtime effects. Omitting it, or using different
    // parameter names inside it, cannot turn the remaining zero return into an implementation.
    if (hasCTokens(tokens, start, listOf("if", "(", "0", ")", "{"))) {
        var cursor = skipEmptyCStatements(tokens, start + 5)
        val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
        while (tokens.getOrNull(cursor)?.text == "(") {
            if (tokens.getOrNull(cursor + 1)?.text != "void" || tokens.getOrNull(cursor + 2)?.text != ")" ||
                tokens.getOrNull(cursor + 3)?.text?.matches(identifier) != true ||
                tokens.getOrNull(cursor + 4)?.text != ";") return null
            cursor = skipEmptyCStatements(tokens, cursor + 5)
        }
        if (tokens.getOrNull(cursor)?.text != "}") return null
        start = skipEmptyCStatements(tokens, cursor + 1)
    }
    return start
}

/** A closed zero grammar; expressions with names, casts, binary operators or nonzero elements survive.
 * Iteration uses constant space and at most one visit per consumed token, regardless of nesting.
 */
private fun zeroInitializerEnd(tokens: List<CToken>, start: Int): Int? {
    var cursor = start
    var braces = 0
    var needsValue = true
    while (true) {
        if (needsValue) {
            if (tokens.getOrNull(cursor)?.text == "{") {
                braces++
                cursor++
                continue
            }
            cursor = zeroExpressionEnd(tokens, cursor) ?: return null
            needsValue = false
        } else {
            if (braces == 0) return cursor
            when (tokens.getOrNull(cursor)?.text) {
                "}" -> { braces--; cursor++ }
                "," -> {
                    cursor++
                    if (tokens.getOrNull(cursor)?.text == "}") { braces--; cursor++ }
                    else needsValue = true
                }
                else -> return null
            }
        }
    }
}

private fun zeroExpressionEnd(tokens: List<CToken>, start: Int): Int? {
    var cursor = start
    var parentheses = 0
    while (true) {
        when (tokens.getOrNull(cursor)?.text) {
            "(" -> { parentheses++; cursor++ }
            "+", "-" -> cursor++
            else -> break
        }
    }
    val literal = tokens.getOrNull(cursor)?.text ?: return null
    if (!literal.matches(cIntegerZeroLiteral) && !literal.matches(cFloatingZeroLiteral)) return null
    cursor++
    repeat(parentheses) {
        if (tokens.getOrNull(cursor)?.text != ")") return null
        cursor++
    }
    return cursor
}

// The strict profile does not enable -pedantic: GCC/Clang numeric extensions also
// compile, so they must not provide alternate spellings for a zero placeholder.
private const val cIntegerSuffix = "(?:u(?:l{1,2}|wb)?|(?:l{1,2}|wb)u?)"
private const val cFloatingSuffix = "(?:[fldqw]|f(?:16|32|64|128)x?|bf16|d[fdl])"
private val cIntegerZeroLiteral = Regex(
    "(?i)(?:0+|0x0+|0b0+)(?:$cIntegerSuffix[ij]?|[ij](?:$cIntegerSuffix)?)?",
)

// Match exact zero significands rather than converting to a JVM floating value: conversion
// would underflow small nonzero C constants and wrongly classify real evidence as a stub.
private val cFloatingZeroLiteral = Regex(
    "(?i)(?:(?:0+\\.0*|\\.0+)(?:e[+-]?[0-9]+)?|0+e[+-]?[0-9]+|" +
        "0x(?:0+(?:\\.0*)?|\\.0+)p[+-]?[0-9]+)" +
        "(?:$cFloatingSuffix[ij]?|[ij](?:$cFloatingSuffix)?)?",
)

private fun parenthesizedIdentifierEnd(tokens: List<CToken>, start: Int, name: String): Int? {
    var cursor = start
    while (tokens.getOrNull(cursor)?.text == "(") cursor++
    val parentheses = cursor - start
    if (tokens.getOrNull(cursor)?.text != name) return null
    cursor++
    repeat(parentheses) {
        if (tokens.getOrNull(cursor)?.text != ")") return null
        cursor++
    }
    return cursor
}

/** Call only at a recognized statement boundary, never inside a declaration or control flow. */
private fun skipEmptyCStatements(tokens: List<CToken>, start: Int): Int {
    var cursor = start
    while (tokens.getOrNull(cursor)?.text == ";") cursor++
    return cursor
}

private fun hasCTokens(tokens: List<CToken>, start: Int, expected: List<String>): Boolean =
    expected.indices.all { tokens.getOrNull(start + it)?.text == expected[it] }

/** Recognize retained object declarators that the legacy simple-name recognizer cannot parse. */
internal fun generatedCGlobalDefinition(source: String, name: String): Boolean = runCatching {
    if (generatedCAttributionPreprocessorIssue(source) != null) return@runCatching false
    val tokens = cDeclarationTokens(source, skipDirectives = true)
    var start = 0
    var initializer: Int? = null
    var index = 0
    while (index < tokens.size) {
        when (tokens[index].text) {
            "(", "[" -> index = matchingCToken(tokens, index)
            "=" -> if (initializer == null) initializer = tokens[index].start
            "{" -> {
                var braces = 1
                while (++index < tokens.size && braces > 0) {
                    if (tokens[index].text == "{") braces++
                    if (tokens[index].text == "}") braces--
                }
                if (initializer == null) start = index // A function body or unsupported inline type.
                continue
            }
            ";" -> {
                if (start < index) {
                    val declaration = runCatching {
                        CDeclarationParser(source.substring(tokens[start].start, initializer ?: tokens[index].start)).parse()
                    }.getOrNull()
                    if (declaration?.name?.text == name && declaration.specifiers.none { it == "extern" || it == "typedef" } &&
                        declaration.derived.firstOrNull() !is CDerived.Function) return@runCatching true
                }
                start = index + 1
                initializer = null
            }
        }
        index++
    }
    false
}.getOrDefault(false)

private data class CFunctionDefinition(val declaration: CDeclaration, val bodyStart: Int, val bodyEnd: Int)

private fun findCFunctionDefinition(source: String, names: Set<String>): CFunctionDefinition? {
    if (generatedCAttributionPreprocessorIssue(source) != null) return null
    val tokens = cDeclarationTokens(source, skipDirectives = true)
    var statementStart = 0
    var index = 0
    while (index < tokens.size) {
        when (tokens[index].text) {
            "(", "[" -> index = matchingCToken(tokens, index)
            ";" -> statementStart = index + 1
            "{" -> {
                val declaration = runCatching {
                    CDeclarationParser(source.substring(tokens[statementStart].start, tokens[index].start)).parse()
                }.getOrNull()
                val parameters = declaration?.derived?.firstOrNull() as? CDerived.Function
                val bodyStart = tokens[index].end
                var braces = 1
                while (++index < tokens.size && braces > 0) {
                    if (tokens[index].text == "{") braces++
                    if (tokens[index].text == "}") braces--
                }
                require(braces == 0) { "unclosed function body" }
                if (declaration?.name?.text in names && parameters != null) {
                    return CFunctionDefinition(requireNotNull(declaration), bodyStart, tokens[index - 1].start)
                }
                statementStart = index
                continue
            }
        }
        index++
    }
    return null
}

/** A dead branch marks adjusted array/function parameters used without reading volatile values. */
private fun unusedParameterReferences(names: List<String>): String = if (names.isEmpty()) "" else
    "    if (0) {\n" + names.joinToString("") { "        (void)$it;\n" } + "    }\n"

private inline fun <T> declarationFor(entityId: String, block: () -> T): T = try {
    block()
} catch (failure: IllegalArgumentException) {
    throw IllegalArgumentException("unsupported generated-C declaration for $entityId: ${failure.message}", failure)
} catch (failure: IllegalStateException) {
    throw IllegalArgumentException("unsupported generated-C declaration for $entityId: ${failure.message}", failure)
}

internal data class CToken(val text: String, val start: Int, val end: Int)
internal sealed interface CDerived {
    data class Pointer(val atomic: Boolean = false) : CDerived
    data class Array(val hasBound: Boolean, val prototypeOnlyStar: Boolean = false, val start: Int = 0, val end: Int = 0) : CDerived
    data class Function(
        val start: Int,
        val end: Int,
        val parameters: List<CDeclaration>,
        val explicitVoid: Boolean,
        val parameterStarts: List<Int> = emptyList(),
    ) : CDerived
}
internal data class CDeclaration(
    val source: String,
    val specifiers: List<String>,
    val storageSpecifiers: List<CToken>,
    val declaratorOffset: Int,
    val name: CToken?,
    val nameOffset: Int,
    /** Declarator operations ordered from the identifier outward. */
    val derived: List<CDerived>,
    /** Parsed type-name of an atomic specifier, distinct from the `_Atomic` qualifier. */
    val atomicType: CDeclaration? = null,
)

/**
 * A deliberately bounded C declarator parser, not a type resolver. Identifiers in the type
 * position are retained even when undeclared; the strict compiler owns that diagnostic.
 * Unsupported extensions/inline type definitions fail explicitly rather than changing the ABI.
 */
private class CDeclarationParser(raw: String, private val symbolicName: String? = null, private val depth: Int = 0, private val work: COrderWork? = null) {
    private var trailingLineComment = false
    private val tokens = cDeclarationTokens(raw, symbolicName, work = work) { trailingLineComment = true }
    private val raw = if (trailingLineComment) "$raw\n" else raw
    private var cursor = 0

    fun parse(allowAbstract: Boolean = false, allowSemicolon: Boolean = true): CDeclaration {
        work?.step()
        require(depth < 64) { "declarator nesting exceeds 64" }
        require(tokens.isNotEmpty()) { "empty declaration" }
        val specifiers = mutableListOf<String>()
        val storageSpecifiers = mutableListOf<CToken>()
        var atomicType: CDeclaration? = null
        var hasType = false
        while (cursor < tokens.size) {
            work?.step()
            val token = tokens[cursor].text
            when {
                token == "_Atomic" && tokens.getOrNull(cursor + 1)?.text == "(" -> {
                    require(atomicType == null) { "multiple atomic type specifiers are unsupported" }
                    val start = tokens[cursor].start
                    val end = matchingCToken(tokens, cursor + 1, work)
                    atomicType = CDeclarationParser(raw.cOrderSlice(tokens[cursor + 1].end, tokens[end].start, work = work), depth = depth + 1, work = work)
                        .parse(allowAbstract = true, allowSemicolon = false)
                    require(atomicType.name == null && atomicType.storageSpecifiers.isEmpty()) {
                        "an atomic type-name must be abstract and have no storage specifiers"
                    }
                    specifiers += raw.cOrderSlice(start, tokens[end].end, work = work)
                    hasType = true
                    cursor = end + 1
                }
                token in qualifiers -> { specifiers += token; cursor++ }
                token in cStorageSpecifiers -> {
                    storageSpecifiers += tokens[cursor]
                    specifiers += token
                    cursor++
                }
                token in builtinTypes -> { specifiers += token; hasType = true; cursor++ }
                token in setOf("struct", "union", "enum") -> {
                    specifiers += token
                    cursor++
                    require(tokens.getOrNull(cursor)?.text?.matches(identifier) == true) { "$token requires a named tag" }
                    specifiers += tokens[cursor++].text
                    hasType = true
                }
                !hasType && token.matches(identifier) -> { specifiers += token; hasType = true; cursor++ }
                else -> break
            }
        }
        require(hasType) { "missing declared type" }
        val declaratorOffset = tokens.getOrNull(cursor)?.start ?: this.raw.length
        val declarator = declarator(allowAbstract, 0)
        val semicolon = tokens.getOrNull(cursor)?.takeIf { it.text == ";" }
        require(allowSemicolon || semicolon == null) { "semicolon is not allowed in a parameter" }
        if (semicolon != null) cursor++
        require(cursor == tokens.size) { "unexpected token ${tokens[cursor].text}" }
        val source = if (semicolon == null) raw else raw.removeRange(semicolon.start, semicolon.end)
        return CDeclaration(source, specifiers, storageSpecifiers, declaratorOffset, declarator.name, declarator.nameOffset, declarator.derived, atomicType)
    }

    private data class Declarator(val name: CToken?, val nameOffset: Int, val derived: List<CDerived>)

    private fun declarator(allowAbstract: Boolean, nesting: Int): Declarator {
        work?.step()
        require(nesting < 64) { "declarator nesting exceeds 64" }
        val pointers = mutableListOf<CDerived.Pointer>()
        while (tokens.getOrNull(cursor)?.text == "*") {
            work?.step()
            cursor++
            var atomic = false
            while (tokens.getOrNull(cursor)?.text in qualifiers) {
                work?.step()
                atomic = atomic || tokens[cursor].text == "_Atomic"
                cursor++
            }
            pointers += CDerived.Pointer(atomic)
        }
        var name: CToken? = null
        var nameOffset = tokens.getOrNull(cursor)?.start ?: tokens.last().end
        val derived = mutableListOf<CDerived>()
        val next = tokens.getOrNull(cursor)
        when {
            next != null && (next.text.matches(identifier) || next.text == symbolicName) -> {
                name = next
                cursor++
            }
            next?.text == "(" && (!allowAbstract || tokens.getOrNull(cursor + 1)?.text in setOf("*", "(") ||
                (tokens.getOrNull(cursor + 1)?.text?.matches(identifier) == true &&
                    tokens[cursor + 1].text !in builtinTypes && tokens.getOrNull(cursor + 2)?.text == ")")) -> {
                cursor++
                val nested = declarator(allowAbstract, nesting + 1)
                require(tokens.getOrNull(cursor)?.text == ")") { "unclosed parenthesized declarator" }
                cursor++
                name = nested.name
                nameOffset = nested.nameOffset
                derived += nested.derived
            }
            !allowAbstract -> error("missing function or parameter declarator")
        }
        while (cursor < tokens.size) {
            work?.step()
            when (tokens[cursor].text) {
                "(" -> {
                    val end = matchingCToken(tokens, cursor, work)
                    derived += parameterList(raw, tokens, cursor, end, depth + 1, work)
                    cursor = end + 1
                }
                "[" -> {
                    val end = matchingCToken(tokens, cursor, work)
                    val bound = tokens.subList(cursor + 1, end).map { work?.step(); it.text }.filterNot { work?.step(); it in qualifiers }
                    derived += CDerived.Array(hasBound = end > cursor + 1, prototypeOnlyStar = bound == listOf("*"), start = tokens[cursor].start, end = tokens[end].end)
                    cursor = end + 1
                }
                else -> break
            }
        }
        for (pointer in pointers.asReversed()) { work?.step(); derived += pointer }
        return Declarator(name, nameOffset, derived)
    }

    companion object {
        private val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
        private val qualifiers = setOf("const", "volatile", "restrict", "_Atomic")
        private val builtinTypes = setOf("void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex")

        fun parameterList(source: String, tokens: List<CToken>, start: Int, end: Int, depth: Int = 0, work: COrderWork? = null): CDerived.Function {
            if (end == start + 2 && tokens[start + 1].text == "void") {
                return CDerived.Function(tokens[start].start, tokens[end].end, emptyList(), true)
            }
            val parameters = mutableListOf<CDeclaration>()
            val parameterStarts = mutableListOf<Int>()
            var cursor = start + 1
            while (cursor < end) {
                work?.step()
                val first = cursor
                while (cursor < end && tokens[cursor].text != ",") {
                    work?.step()
                    cursor = if (tokens[cursor].text in setOf("(", "[")) matchingCToken(tokens, cursor, work) + 1 else cursor + 1
                }
                require(cursor > first) { "empty parameter declaration" }
                if (cursor == first + 1 && tokens[first].text == "...") {
                    require(parameters.isNotEmpty() && cursor == end) { "ellipsis requires preceding parameters and must be last" }
                } else {
                    val parameter = CDeclarationParser(source.cOrderSlice(tokens[first].start, tokens[cursor - 1].end, work = work), depth = depth, work = work)
                        .parse(allowAbstract = true, allowSemicolon = false)
                    require(parameter.specifiers != listOf("void") || parameter.derived.isNotEmpty()) { "void must be the only parameter" }
                    parameters += parameter
                    parameterStarts += tokens[first].start
                }
                if (cursor < end) {
                    cursor++
                    require(cursor < end) { "trailing parameter comma" }
                }
            }
            return CDerived.Function(tokens[start].start, tokens[end].end, parameters, false, parameterStarts.toList())
        }
    }
}

private val cStorageSpecifiers = setOf("extern", "static", "register", "auto", "inline", "_Noreturn", "_Thread_local", "typedef")

/** End offset for C physical-line joining, including the already guarded trigraph/whitespace forms. */
internal fun generatedCPhysicalLineSpliceEnd(source: String, start: Int): Int? = cPhysicalLineSpliceEnd(source, start)

private fun cPhysicalLineSpliceEnd(source: String, start: Int, work: COrderWork? = null): Int? {
    var cursor = when {
        source[start] == '\\' -> start + 1
        source.startsWith("??/", start) -> start + 3
        else -> return null
    }
    while (cursor < source.length && source[cursor] in " \t\u000b\u000c") { work?.step(); cursor++ }
    return when (source.getOrNull(cursor)) {
        '\n' -> cursor + 1
        '\r' -> cursor + if (source.getOrNull(cursor + 1) == '\n') 2 else 1
        else -> null
    }
}

/** Lexical offsets let rendering retain original whitespace, qualifiers, and comments. */
private fun cDeclarationTokens(
    source: String,
    symbolicName: String? = null,
    skipDirectives: Boolean = false,
    work: COrderWork? = null,
    onTrailingLineComment: () -> Unit = {},
): List<CToken> {
    work?.span(source.length)
    val result = mutableListOf<CToken>()
    var cursor = 0
    while (cursor < source.length) {
        work?.step()
        val start = cursor
        when {
            source[cursor].isWhitespace() -> cursor++
            skipDirectives && source[cursor] == '#' && source.cOrderSlice(source.lastIndexOf('\n', cursor) + 1, cursor, work = work).isBlank() -> {
                cursor = source.indexOf('\n', cursor).let { if (it < 0) source.length else it }
            }
            source.startsWith("//", cursor) -> {
                var newline = cursor
                while (newline < source.length && source[newline] != '\r' && source[newline] != '\n') { work?.step(); newline++ }
                if (newline == source.length) newline = -1
                val end = if (newline < 0) source.length else newline
                var last = end - 1
                while (last > cursor && source[last].isWhitespace()) { work?.step(); last-- }
                // Translation splices escaped physical newlines before removing comments.
                // Even a blank following line triggers -Wcomment under the strict profile.
                val escaped = source[last] == '\\' || (last >= 2 && source.regionMatches(last - 2, "??/", 0, 3))
                require(!escaped) { "a line comment ending in backslash cannot safely precede generated C syntax" }
                cursor = if (newline < 0) { onTrailingLineComment(); source.length } else newline
            }
            source.startsWith("/*", cursor) -> {
                var end = cursor + 2
                while (end + 1 < source.length && !source.startsWith("*/", end)) { work?.step(); end++ }
                require(end + 1 < source.length) { "unclosed comment" }
                cursor = end + 2
            }
            source[cursor] == '"' || source[cursor] == '\'' -> {
                val quote = source[cursor++]
                var escaped = false
                var closed = false
                while (cursor < source.length) {
                    work?.step()
                    val spliceEnd = cPhysicalLineSpliceEnd(source, cursor, work)
                    if (spliceEnd != null) {
                        cursor = spliceEnd
                        continue
                    }
                    val character = if (source.startsWith("??/", cursor)) { cursor += 3; '\\' } else source[cursor++]
                    when {
                        escaped -> escaped = false
                        character == '\\' -> escaped = true
                        character == quote -> { closed = true; break }
                    }
                }
                require(closed) { "unclosed literal" }
                result += CToken(source.cOrderSlice(start, cursor, work = work), start, cursor)
            }
            symbolicName?.isNotEmpty() == true && source.startsWith(symbolicName, cursor) &&
                source.getOrNull(cursor + symbolicName.length)?.let { !it.isLetterOrDigit() && it != '_' } != false -> {
                cursor += symbolicName.length
                result += CToken(symbolicName, start, cursor)
            }
            source[cursor].isDigit() || (source[cursor] == '.' && source.getOrNull(cursor + 1)?.isDigit() == true) -> {
                // Keep a C preprocessing-number together, including decimal points and signed
                // exponents. The zero recognizer then validates the entire numeric spelling.
                cursor++
                while (cursor < source.length && (source[cursor].isLetterOrDigit() || source[cursor] in "_." ||
                    (source[cursor] in "+-" && source[cursor - 1] in "eEpP"))) { work?.step(); cursor++ }
                result += CToken(source.cOrderSlice(start, cursor, work = work), start, cursor)
            }
            source[cursor].isLetterOrDigit() || source[cursor] == '_' -> {
                do { work?.step(); cursor++ } while (cursor < source.length && (source[cursor].isLetterOrDigit() || source[cursor] == '_'))
                result += CToken(source.cOrderSlice(start, cursor, work = work), start, cursor)
            }
            source.startsWith("...", cursor) -> {
                cursor += 3
                result += CToken("...", start, cursor)
            }
            else -> { cursor++; result += CToken(source.cOrderSlice(start, cursor, work = work), start, cursor) }
        }
    }
    return result
}

private fun matchingCToken(tokens: List<CToken>, start: Int, work: COrderWork? = null): Int {
    val stack = mutableListOf<String>()
    for (index in start until tokens.size) {
        work?.step()
        when (tokens[index].text) {
            "(", "[" -> stack += tokens[index].text
            ")", "]" -> {
                require(stack.isNotEmpty() && stack.removeAt(stack.lastIndex) == if (tokens[index].text == ")") "(" else "[") {
                    "unbalanced declarator delimiters"
                }
                if (stack.isEmpty()) return index
            }
        }
    }
    error("unclosed declarator delimiter")
}

internal fun safeCName(name: String): String {
    val sanitized = name.replace(Regex("[^A-Za-z0-9_]+"), "_").ifBlank { "recovered" }
    val collision = sanitized in setOf("_init", "_fini", "_start", "stdin", "stdout", "stderr") || sanitized.startsWith("__")
    return when {
        sanitized.first().isDigit() -> "fn_$sanitized"
        collision -> "recovered_$sanitized"
        else -> sanitized
    }
}

/** A single ordering operation owns this meter, including optional parsing and cache hits. */
private class COrderWork(val checkpoint: () -> Unit, val charge: (Long) -> Unit) {
    fun step() { checkpoint(); charge(1) }
    fun span(length: Int) {
        charge(length.toLong())
        var offset = 0
        while (offset < length) { checkpoint(); offset += 256 }
        checkpoint()
    }
}

internal sealed interface COrderSymbol {
    data class Alias(val name: String) : COrderSymbol
    data class Tag(val name: String) : COrderSymbol
    data class Enumerator(val name: String) : COrderSymbol
}
internal data class COrderSite(val ownerId: String, val originalOffset: Int, val scopeId: Int)
internal enum class COrderNeed { ALIAS_DECL, TAG_VISIBLE, COMPLETE_BODY, ENUM_VALUE }
internal data class COrderUse(val site: COrderSite, val symbol: COrderSymbol, val need: COrderNeed)
internal data class COrderExport(
    val site: COrderSite, val symbol: COrderSymbol, val tagKind: String?,
    val signature: List<String>, val availableOffset: Int, val definition: Boolean,
)
internal data class COrderScope(val id: Int, val parent: Int?, val ownerId: String, val start: Int, val end: Int)
internal data class COrderInventory(
    val exports: List<COrderExport>, val uses: List<COrderUse>, val scopes: List<COrderScope>,
)

/** The only bridge from the private declaration machinery to record ordering. */
internal fun generatedCTypeOrderInventory(
    types: List<RecoveredType>, checkpoint: () -> Unit, charge: (Long) -> Unit,
): COrderInventory = COrderInventoryBuilder(types, COrderWork(checkpoint, charge)).build()

private sealed interface COrderShape {
    data object Scalar : COrderShape
    // A member's container has been completed, but its field type is not inferred.
    data object MemberResult : COrderShape
    data class Tag(val name: String, val site: COrderSite) : COrderShape
    data class Anonymous(val site: COrderSite, val completed: Int) : COrderShape
    data class Alias(val name: String) : COrderShape
    data class Pointer(val inner: COrderShape) : COrderShape
    data class Array(val inner: COrderShape, val sized: Boolean) : COrderShape
    data class Function(val result: COrderShape) : COrderShape
    data class Atomic(val inner: COrderShape) : COrderShape
}

// Expression shapes keep declaration-site tag identities until aliases can be resolved.
// They describe only direct operations; member result types are deliberately unproven.
private sealed interface COrderExpression {
    data object Unknown : COrderExpression
    data class Value(val shape: COrderShape, val operand: COrderExpression? = null) : COrderExpression
    data class Unary(val operator: String, val operand: COrderExpression) : COrderExpression
    data class Member(val target: COrderExpression, val pointer: Boolean) : COrderExpression
    data class Sequence(val operands: List<COrderExpression>, val comma: Boolean) : COrderExpression
    data class Call(val operands: List<COrderExpression>) : COrderExpression
}

private data class COrderOpaqueUse(val site: COrderSite, val source: String)

private class COrderInventoryBuilder(val types: List<RecoveredType>, val work: COrderWork) {
    private val index = cTypeIndex(types, work)
    private val exports = mutableListOf<COrderExport>()
    private val uses = linkedSetOf<COrderUse>()
    private val scopes = mutableListOf(COrderScope(0, null, "", 0, Int.MAX_VALUE))
    private val aliases = linkedMapOf<String, COrderShape>()
    private val objects = mutableListOf<Triple<COrderShape, COrderSite, Boolean>>()
    private val expressions = mutableListOf<Pair<COrderExpression, COrderSite>>()
    private val opaqueUses = mutableListOf<COrderOpaqueUse>()
    private val bodies = hashSetOf<COrderSite>()
    private val ordinary = mutableMapOf<Int, MutableList<Pair<String, COrderSite>>>()
    private val ordinaryShapes = mutableMapOf<COrderSite, COrderShape>()
    private val tagEvents = mutableListOf<COrderExport>()
    private val tagEventSites = hashSetOf<COrderSite>()
    private val tagBindings = mutableMapOf<COrderSite, COrderExport>()
    private val sources = types.associate { work.step(); it.id to it.declaration }
    private val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
    private val kinds = setOf("struct", "union", "enum")
    private val qualifiers = setOf("const", "volatile", "restrict", "_Atomic")
    private val builtins = setOf("void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex")
    private val shapeCache = mutableMapOf<String, Pair<COrderShape, Int>>()

    private fun addExport(value: COrderExport) {
        work.step()
        require(exports.size < 131_072) { "recovered type dependency inventory exceeds its bound" }
        exports += value
    }
    private fun use(site: COrderSite, symbol: COrderSymbol, need: COrderNeed) {
        work.step(); uses += COrderUse(site, symbol, need)
    }
    private fun site(owner: String, offset: Int, scope: Int) = COrderSite(owner, offset, scope)
    private fun before(a: COrderSite, b: COrderSite): Boolean =
        a.ownerId < b.ownerId || a.ownerId == b.ownerId && a.originalOffset <= b.originalOffset
    private fun shadowed(name: String, at: COrderSite): Boolean {
        var scope: Int? = at.scopeId
        while (scope != null) {
            work.step()
            if (ordinary[scope].orEmpty().any { (n, position) -> work.step(); n == name && before(position, at) }) return true
            scope = scopes[scope].parent
        }
        return false
    }
    private fun bind(name: String, at: COrderSite, shape: COrderShape = COrderShape.Scalar) {
        work.step()
        ordinary.getOrPut(at.scopeId) { mutableListOf() } += name to at
        ordinaryShapes[at] = shape
    }
    private fun ordinaryShape(name: String, at: COrderSite): COrderShape? {
        var scope: Int? = at.scopeId
        while (scope != null) {
            work.step()
            val binding = ordinary[scope].orEmpty().lastOrNull { (n, position) -> work.step(); n == name && before(position, at) }
            if (binding != null) return ordinaryShapes.getValue(binding.second)
            scope = scopes[scope].parent
        }
        return null
    }

    fun build(): COrderInventory {
        // Compatibility is the selector's original per-alias/original-body token comparison.
        for ((name, candidates) in index.exports) {
            work.step()
            val definitions = candidates.filter { work.step(); it.definition }.ifEmpty { candidates }
            val signature = definitions.first().signature
            require(definitions.all { entry ->
                entry.signature.size == signature.size && signature.indices.all { offset ->
                    work.step(); entry.signature[offset] == signature[offset]
                }
            }) { "ambiguous recovered type dependency $name in ${definitions.map { it.type.id }.distinct().sorted()}" }
            if (name.startsWith("tag:")) require(candidates.all { work.step(); it.signature.first() == signature.first() }) {
                "ambiguous recovered type dependency $name"
            }
        }
        for (type in types) {
            work.step()
            for (part in splitCTypeSourceParts(type.declaration, ";", work)) {
                visit(part.source, type.id, part.start, 0, false, 0)
            }
        }
        opaqueUses.forEach { opaque(it) }
        bindTags()
        for ((shape, at, complete) in objects) {
            work.step()
            constructors(shape, at, 0)
            if (complete) complete(shape, at, 0)
        }
        for ((expression, at) in expressions) expressionShape(expression, at, 0)
        val signatures = java.util.IdentityHashMap<List<String>, List<String>>()
        val frozenExports = exports.map { export ->
            work.step()
            val signature = signatures.getOrPut(export.signature) { frozen(export.signature) }
            export.copy(signature = signature)
        }
        return COrderInventory(frozen(frozenExports), frozen(uses), frozen(scopes))
    }

    private fun <T> frozen(values: Collection<T>): List<T> {
        work.span(values.size)
        return java.util.Collections.unmodifiableList(ArrayList(values))
    }

    /** Remove only parser envelopes, preserving offsets; their operands are visited separately. */
    private fun envelopes(source: String, owner: String, start: Int, scope: Int, depth: Int): String {
        work.span(source.length)
        val text = StringBuilder(source)
        val tokens = cDeclarationTokens(source, work = work)
        var i = 0
        while (i < tokens.size) {
            work.step()
            val token = tokens[i]
            if (token.text in setOf("_Alignas", "__attribute__", "__attribute") && tokens.getOrNull(i + 1)?.text == "(") {
                val end = matchingCToken(tokens, i + 1, work)
                expression(source.cOrderSlice(tokens[i + 1].end, tokens[end].start, work = work), owner,
                    start + tokens[i + 1].end, scope, depth + 1, typeOperand = token.text == "_Alignas")
                for (offset in token.start until tokens[end].end) { work.step(); text.setCharAt(offset, ' ') }
                i = end + 1
            } else if (token.text in setOf("(", "[", "{")) {
                i = if (token.text == "{") matchingCTypeBody(tokens, i, work) + 1 else matchingCToken(tokens, i, work) + 1
            } else i++
        }
        return text.toString()
    }

    private fun visit(source: String, owner: String, start: Int, scope: Int, member: Boolean, depth: Int) {
        work.step()
        require(depth <= 64) { "recovered type aggregate nesting exceeds 64" }
        val originalTokens = cDeclarationTokens(source, work = work)
        if (originalTokens.isEmpty()) return
        val cleaned = envelopes(source, owner, start, scope, depth)
        val view = aliasParsingSourceView(cleaned, work = work)
        val parts = splitCTypeSourceParts(view.source, ",", work)
        var first: CDeclaration? = null
        var prefix = ""
        for ((number, part) in parts.withIndex()) {
            work.step()
            val fragment = if (number == 0) part.source else prefix + part.source
            fun viewOffset(offset: Int) = if (number == 0 || offset < prefix.length) offset else part.start + offset - prefix.length
            fun original(offset: Int): Int {
                val v = viewOffset(offset)
                val replacement = view.replacements.firstOrNull { work.step(); v >= it.viewStart && v < it.viewEnd }
                return start + (replacement?.originalStart ?: view.originalOffset(v))
            }
            val tokens = cDeclarationTokens(fragment, work = work)
            var stop = fragment.length
            var i = 0
            while (i < tokens.size) {
                work.step()
                when (tokens[i].text) {
                    "(", "[" -> i = matchingCToken(tokens, i, work)
                    "=", ":" -> {
                        stop = tokens[i].start
                        val expressionStart = tokens[i].end
                        expression(fragment.cOrderSlice(expressionStart, work = work), owner, original(expressionStart), scope, depth + 1)
                        break
                    }
                }
                i++
            }
            val declaration = try {
                CDeclarationParser(fragment.cOrderSlice(0, stop, work = work), work = work).parse(allowAbstract = true)
            } catch (_: IllegalArgumentException) { null } catch (_: IllegalStateException) { null }
            if (declaration == null) {
                // Recover the proven leading specifiers even when an extension makes only
                // the following declarator opaque. Aggregate bodies still get their own walk.
                var leading = 0
                var hasType = false
                while (leading < tokens.size) {
                    work.step()
                    val token = tokens[leading].text
                    when {
                        token == "_Atomic" && tokens.getOrNull(leading + 1)?.text == "(" -> {
                            hasType = true; leading = matchingCToken(tokens, leading + 1, work) + 1
                        }
                        token in kinds -> { hasType = true; leading += 2 }
                        token in qualifiers || token in cStorageSpecifiers -> leading++
                        token in builtins -> { hasType = true; leading++ }
                        !hasType && token.matches(identifier) -> { hasType = true; leading++ }
                        else -> break
                    }
                }
                val boundary = tokens.getOrNull(leading)?.start ?: stop
                if (hasType && boundary > 0) {
                    val base = CDeclarationParser(fragment.cOrderSlice(0, boundary, work = work), work = work).parse(allowAbstract = true)
                    val shape = declaration(base, owner, scope, ::original, depth)
                    objects += Triple(shape, site(owner, original(boundary), scope), member || scope == 0 && "typedef" !in base.specifiers)
                }
                val residualStart = original(boundary)
                opaqueUses += COrderOpaqueUse(site(owner, residualStart, scope),
                    source.cOrderSlice(residualStart - start, work = work))
                return
            }
            if (number == 0) {
                first = declaration
                prefix = declaration.source.cOrderSlice(0, declaration.declaratorOffset, work = work)
            }
            val shape = declaration(declaration, owner, scope, ::original, depth)
            val at = site(owner, original(declaration.name?.start ?: declaration.declaratorOffset), scope)
            if ("typedef" in declaration.specifiers && scope == 0) {
                val name = requireNotNull(declaration.name) { "typedef has no alias name" }.text
                aliases.putIfAbsent(name, shape)
                val signature = index.exports["name:$name"].orEmpty().firstOrNull { it.type.id == owner }?.signature
                    ?: error("missing original alias signature for $name")
                addExport(COrderExport(at, COrderSymbol.Alias(name), null, signature,
                    original(declaration.source.length), true))
            } else if (declaration.name != null && scope != 0 && !member) {
                bind(declaration.name.text, at.copy(originalOffset = original(declaration.source.length)), shape)
            }
            val objectComplete = (member || scope == 0 && declaration.name != null && "extern" !in declaration.specifiers) &&
                "typedef" !in declaration.specifiers && declaration.derived.firstOrNull() !is CDerived.Function
            objects += Triple(shape, at, objectComplete)
        }
        check(first != null)
    }

    private fun declaration(
        decl: CDeclaration, owner: String, scope: Int, original: (Int) -> Int, depth: Int,
    ): COrderShape {
        work.step()
        require(depth < 64) { "declarator nesting exceeds 64" }
        val tokens = cDeclarationTokens(decl.source, work = work)
        var shape: COrderShape = COrderShape.Scalar
        var i = 0
        var hasType = false
        while (i < tokens.size && tokens[i].start < decl.declaratorOffset) {
            work.step()
            val token = tokens[i]
            val at = site(owner, original(token.start), scope)
            when {
                token.text == "_Atomic" && tokens.getOrNull(i + 1)?.text == "(" -> {
                    val end = matchingCToken(tokens, i + 1, work)
                    val offset = tokens[i + 1].end
                    shape = COrderShape.Atomic(declaration(requireNotNull(decl.atomicType), owner, scope,
                        { original(offset + it) }, depth + 1))
                    hasType = true; i = end + 1; continue
                }
                token.text in kinds -> {
                    // A replacement's original start identifies the real aggregate, including anonymous bodies.
                    val source = sources.getValue(owner)
                    val tail = source.cOrderSlice(at.originalOffset, work = work)
                    work.span(tail.length)
                    val actual = cDeclarationTokens(tail, work = work)
                    val tag = actual.getOrNull(1)?.takeIf { it.text.matches(identifier) }
                    val body = if (tag == null) 1 else 2
                    val end = if (actual.getOrNull(body)?.text == "{") matchingCTypeBody(actual, body, work) else null
                    val signature = if (end == null) listOf(token.text, requireNotNull(tag).text) else {
                        work.span(end + 1)
                        actual.take(end + 1).map { work.step(); it.text }
                    }
                    if (tag != null) {
                        val event = COrderExport(at, COrderSymbol.Tag(tag.text), token.text, signature,
                            if (end == null) at.originalOffset else at.originalOffset + actual[end].end, end != null)
                        if (tagEventSites.add(at)) {
                            work.step()
                            require(tagEvents.size < 131_072) { "recovered type dependency inventory exceeds its bound" }
                            tagEvents += event
                        }
                        shape = COrderShape.Tag(tag.text, at)
                    } else {
                        shape = COrderShape.Anonymous(at, at.originalOffset + actual[requireNotNull(end)].end)
                    }
                    if (end != null && bodies.add(at)) {
                        val bodyStart = at.originalOffset + actual[body].end
                        val bodySource = source.cOrderSlice(bodyStart, at.originalOffset + actual[end].start, work = work)
                        if (token.text == "enum") {
                            for (entry in splitCTypeSourceParts(bodySource, ",", work)) {
                                val entryTokens = cDeclarationTokens(entry.source, work = work)
                                val name = entryTokens.first()
                                val enumSite = site(owner, bodyStart + entry.start + name.start, scope)
                                val equals = entryTokens.indexOfFirst { it.text == "=" }
                                if (equals >= 0) {
                                    val offset = entryTokens[equals].end
                                    expression(entry.source.cOrderSlice(offset, work = work), owner, bodyStart + entry.start + offset, scope, depth + 1)
                                }
                                addExport(COrderExport(enumSite, COrderSymbol.Enumerator(name.text), null,
                                    signature, bodyStart + entry.start + entry.source.length, true))
                                if (scope != 0) bind(name.text, enumSite.copy(originalOffset = bodyStart + entry.start + entry.source.length))
                            }
                        } else for (member in splitCTypeSourceParts(bodySource, ";", work)) {
                            visit(member.source, owner, bodyStart + member.start, scope, true, depth + 1)
                        }
                    }
                    hasType = true; i += 2; continue
                }
                token.text in builtins -> { hasType = true }
                token.text in qualifiers || token.text in cStorageSpecifiers -> Unit
                !hasType && token.text.matches(identifier) -> {
                    if (index.exports["name:${token.text}"].orEmpty().any { work.step(); !it.enumerator } && !shadowed(token.text, at)) {
                        use(at, COrderSymbol.Alias(token.text), COrderNeed.ALIAS_DECL)
                        shape = COrderShape.Alias(token.text)
                    }
                    hasType = true
                }
            }
            i++
        }
        if ("_Atomic" in decl.specifiers) shape = COrderShape.Atomic(shape)
        // Parameters are visited at their declaration once, never during alias expansion.
        for (derived in decl.derived) {
            work.step()
            when (derived) {
                is CDerived.Function -> {
                    val id = scopes.size
                    scopes += COrderScope(id, scope, owner, original(derived.start), original(derived.end))
                    for ((index, parameter) in derived.parameters.withIndex()) {
                        val offset = derived.parameterStarts[index]
                        val parameterShape = declaration(parameter, owner, id, { original(offset + it) }, depth + 1)
                        val at = site(owner, original(offset), id)
                        objects += Triple(parameterShape, at, false)
                        parameter.name?.let {
                            val adjusted = when (parameterShape) {
                                is COrderShape.Array -> COrderShape.Pointer(parameterShape.inner)
                                is COrderShape.Function -> COrderShape.Pointer(parameterShape)
                                else -> parameterShape
                            }
                            bind(it.text, site(owner, original(offset + parameter.source.length), id), adjusted)
                        }
                    }
                }
                is CDerived.Array -> if (derived.end > derived.start) {
                    expression(decl.source.cOrderSlice(derived.start + 1, derived.end - 1, work = work), owner,
                        original(derived.start + 1), scope, depth + 1)
                }
                is CDerived.Pointer -> Unit
            }
        }
        for (derived in decl.derived.asReversed()) shape = when (derived) {
            is CDerived.Pointer -> COrderShape.Pointer(shape)
            is CDerived.Array -> COrderShape.Array(shape, derived.hasBound)
            is CDerived.Function -> COrderShape.Function(shape)
        }
        return shape
    }

    private fun expression(source: String, owner: String, start: Int, scope: Int, depth: Int, typeOperand: Boolean = false) {
        work.step()
        require(depth < 64) { "type operand nesting exceeds 64" }
        val parser = DirectExpressionParser(source, owner, start, scope, depth)
        if (typeOperand) parser.typeName(0, parser.tokens.size)?.let { shape ->
            objects += Triple(shape, site(owner, start + source.length, scope), true)
            return
        }
        if (parser.tokens.isEmpty() || parser.tokens.map { work.step(); it.text } == listOf("*")) return
        expressions += parser.parse() to site(owner, start + source.length, scope)
    }

    /** Bounded direct C operations, not a C type checker. Unknown result shapes cannot
     * become member/dereference targets. Arithmetic with a known pointer, subscripting,
     * conditional expressions and generic selections refuse instead of guessing a target. */
    private inner class DirectExpressionParser(
        val source: String, val owner: String, val start: Int, val scope: Int, val depth: Int,
    ) {
        val tokens = cDeclarationTokens(source, work = work)
        var cursor = 0
        fun unsupported(): Nothing = throw IllegalArgumentException(
            "unsupported generated-C direct expression in $owner at ${start + (tokens.getOrNull(cursor)?.start ?: source.length)}")

        fun typeName(first: Int, end: Int): COrderShape? {
            work.step()
            val head = tokens.getOrNull(first)?.takeIf { first < end } ?: return null
            val at = site(owner, start + head.start, scope)
            if (head.text !in kinds && head.text !in builtins && head.text !in qualifiers &&
                (index.exports["name:${head.text}"].orEmpty().none { work.step(); !it.enumerator } || shadowed(head.text, at))) return null
            val text = source.cOrderSlice(head.start, tokens[end - 1].end, work = work)
            val view = aliasParsingSourceView(text, work = work)
            val parsed = try { CDeclarationParser(view.source, work = work).parse(allowAbstract = true, allowSemicolon = false) }
                catch (_: IllegalArgumentException) { return null } catch (_: IllegalStateException) { return null }
            if (parsed.name != null) return null
            val shape = declaration(parsed, owner, scope, { position ->
                val replacement = view.replacements.firstOrNull { work.step(); position >= it.viewStart && position < it.viewEnd }
                start + head.start + (replacement?.originalStart ?: view.originalOffset(position))
            }, depth + 1)
            objects += Triple(shape, site(owner, start + tokens[end - 1].end, scope), false)
            return shape
        }

        fun parse(): COrderExpression {
            // Array parameter qualifiers do not form part of the bound expression.
            while (tokens.getOrNull(cursor)?.text in qualifiers || tokens.getOrNull(cursor)?.text == "static") { work.step(); cursor++ }
            val result = sequence(0)
            if (cursor != tokens.size) unsupported()
            return result
        }

        private fun sequence(nesting: Int): COrderExpression {
            val values = mutableListOf(binary(nesting))
            while (tokens.getOrNull(cursor)?.text == ",") { work.step(); cursor++; values += binary(nesting) }
            return if (values.size == 1) values.single() else COrderExpression.Sequence(values, true)
        }

        private fun binary(nesting: Int): COrderExpression {
            // All supported binary operands must prove non-pointer shapes at evaluation.
            // Their scalar result has no type-body prerequisite, so precedence is irrelevant
            // to this shape projection. Comma alone preserves its final operand's shape.
            val values = mutableListOf(unary(nesting))
            while (tokens.getOrNull(cursor)?.text in setOf("+", "-", "/", "%", "*", "&", "|", "^", "<", ">", "=", "!")) {
                work.step()
                val operator = tokens[cursor++].text
                val next = tokens.getOrNull(cursor)?.text
                if (next == operator && operator in setOf("&", "|", "<", ">") || next == "=" && operator in setOf("=", "!", "<", ">")) { work.step(); cursor++ }
                else if (operator in setOf("=", "!")) unsupported()
                values += unary(nesting)
            }
            return if (values.size == 1) values.single() else COrderExpression.Sequence(values, false)
        }

        private fun unary(nesting: Int): COrderExpression {
            work.step()
            require(depth + nesting < 64) { "type expression nesting exceeds 64" }
            val token = tokens.getOrNull(cursor) ?: unsupported()
            if (token.text in setOf("sizeof", "_Alignof", "_Alignas")) {
                cursor++
                if (tokens.getOrNull(cursor)?.text == "(") {
                    val end = matchingCToken(tokens, cursor, work)
                    val shape = typeName(cursor + 1, end)
                    if (shape != null) {
                        cursor = end + 1
                        return COrderExpression.Unary(token.text, COrderExpression.Value(shape))
                    }
                }
                return COrderExpression.Unary(token.text, unary(nesting + 1))
            }
            if (token.text in setOf("*", "&", "+", "-", "!", "~")) {
                cursor++
                return COrderExpression.Unary(token.text, unary(nesting + 1))
            }
            var value: COrderExpression
            if (token.text == "(") {
                val end = matchingCToken(tokens, cursor, work)
                val shape = typeName(cursor + 1, end)
                if (shape != null) {
                    cursor = end + 1
                    if (tokens.getOrNull(cursor)?.text == "{") {
                        // Only expression-list initializers are supported here. Designators
                        // and nested initializer syntax must not bypass target analysis.
                        cursor++
                        val initializer = sequence(nesting + 1)
                        if (tokens.getOrNull(cursor)?.text != "}") unsupported()
                        cursor++
                        objects += Triple(shape, site(owner, start + tokens[cursor - 1].end, scope), true)
                        value = COrderExpression.Value(shape, initializer)
                    } else return COrderExpression.Value(shape, unary(nesting + 1))
                } else {
                    cursor++
                    value = sequence(nesting + 1)
                    if (tokens.getOrNull(cursor)?.text != ")") unsupported()
                    cursor++
                }
            } else {
                if (token.text == "_Generic" || !(token.text.matches(identifier) || token.text.first().isDigit() ||
                        token.text.first() in "\"'")) unsupported()
                val at = site(owner, start + token.start, scope)
                val enumerator = token.text.matches(identifier) && !shadowed(token.text, at) &&
                    index.exports["name:${token.text}"].orEmpty().any { work.step(); it.enumerator }
                if (enumerator) use(at, COrderSymbol.Enumerator(token.text), COrderNeed.ENUM_VALUE)
                value = if (enumerator || token.text.first().isDigit() || token.text.first() == '\'')
                    COrderExpression.Value(COrderShape.Scalar)
                else if (token.text.first() == '"') COrderExpression.Value(COrderShape.Array(COrderShape.Scalar, true))
                else ordinaryShape(token.text, at)?.let { COrderExpression.Value(it) } ?: COrderExpression.Unknown
                cursor++
            }
            while (cursor < tokens.size) {
                work.step()
                val pointer = tokens[cursor].text == "-" && tokens.getOrNull(cursor + 1)?.text == ">"
                when {
                    pointer || tokens[cursor].text == "." -> {
                        cursor += if (pointer) 2 else 1
                        if (tokens.getOrNull(cursor)?.text?.matches(identifier) != true) unsupported()
                        cursor++ // Member names never bind typedef or enumerator uses.
                        value = COrderExpression.Member(value, pointer)
                    }
                    tokens[cursor].text == "(" -> {
                        // These attribute envelopes carry expression arguments but no C
                        // call result. General call/return type inference is unsupported.
                        if (token.text !in setOf("aligned", "__aligned__", "packed", "__packed__") ||
                            value !== COrderExpression.Unknown) unsupported()
                        cursor++
                        val arguments = if (tokens.getOrNull(cursor)?.text == ")") emptyList() else listOf(sequence(nesting + 1))
                        if (tokens.getOrNull(cursor)?.text != ")") unsupported()
                        cursor++
                        value = COrderExpression.Call(listOf(value) + arguments)
                    }
                    else -> return value
                }
            }
            return value
        }
    }

    private fun expressionShape(expression: COrderExpression, at: COrderSite, depth: Int): COrderShape? {
        work.step()
        require(depth < 64) { "type expression resolution exceeds depth 64" }
        fun shape(value: COrderExpression) = expressionShape(value, at, depth + 1)
        fun resolved(value: COrderShape?) = value?.let { resolve(it, linkedSetOf(), 0).first }
        fun target(value: COrderShape?): COrderShape {
            val pointer = resolved(value)
            require(pointer is COrderShape.Pointer) { "unsupported generated-C direct expression target in ${at.ownerId}" }
            return pointer.inner
        }
        fun scalar(value: COrderShape?) {
            require(value != null && resolved(value) == COrderShape.Scalar) {
                "unsupported generated-C direct expression operator in ${at.ownerId}"
            }
        }
        return when (expression) {
            COrderExpression.Unknown -> null
            is COrderExpression.Value -> { expression.operand?.let { shape(it) }; expression.shape }
            is COrderExpression.Unary -> {
                val operand = shape(expression.operand)
                when (expression.operator) {
                    "*" -> target(operand)
                    "&" -> operand?.let { COrderShape.Pointer(it) }
                    "sizeof", "_Alignof", "_Alignas" -> {
                        require(operand != null) { "unsupported generated-C direct expression size operand in ${at.ownerId}" }
                        complete(operand, at, 0)
                        COrderShape.Scalar
                    }
                    else -> { scalar(operand); COrderShape.Scalar }
                }
            }
            is COrderExpression.Member -> {
                val operand = shape(expression.target)
                val aggregate = if (expression.pointer) target(operand) else resolved(operand)
                require(aggregate is COrderShape.Tag || aggregate is COrderShape.Anonymous) {
                    "unsupported generated-C direct expression member target in ${at.ownerId}"
                }
                complete(aggregate, at, 0)
                COrderShape.MemberResult // Subsequent dereference/member/arithmetic must refuse.
            }
            is COrderExpression.Sequence -> {
                var result: COrderShape? = null
                for (operand in expression.operands) {
                    work.step(); result = shape(operand)
                    if (!expression.comma) scalar(result)
                }
                if (expression.comma) result else COrderShape.Scalar
            }
            is COrderExpression.Call -> {
                for (operand in expression.operands) { work.step(); shape(operand) }
                COrderShape.Scalar // Only the explicitly parsed attribute envelopes reach here.
            }
        }
    }

    private fun opaque(span: COrderOpaqueUse) {
        // Only the unproven residual is conservative. Proven enclosing specifiers and
        // independent aggregate members never inherit an extension's unknown parameter scope.
        val (origin, source) = span
        val tokens = cDeclarationTokens(source, work = work)
        var parentheses = 0
        var i = 0
        while (i < tokens.size) {
            work.step()
            val token = tokens[i]
            val at = origin.copy(originalOffset = origin.originalOffset + token.start)
            if (token.text == "(") parentheses++
            if (token.text == ")") parentheses--
            if (token.text in kinds && tokens.getOrNull(i + 1)?.text?.matches(identifier) == true) {
                val name = tokens[i + 1].text
                require(parentheses == 0) { "ambiguous generated-C prototype tag dependency in ${origin.ownerId}: ${token.text} $name" }
                tagEvents += COrderExport(at, COrderSymbol.Tag(name), token.text, listOf(token.text, name), at.originalOffset, false)
                use(at, COrderSymbol.Tag(name), COrderNeed.COMPLETE_BODY)
                i++
            } else if (!shadowed(token.text, at)) {
                val candidates = index.exports["name:${token.text}"].orEmpty()
                if (candidates.isNotEmpty()) use(at,
                    if (candidates.first().enumerator) COrderSymbol.Enumerator(token.text) else COrderSymbol.Alias(token.text),
                    if (candidates.first().enumerator) COrderNeed.ENUM_VALUE else COrderNeed.ALIAS_DECL)
            }
            i++
        }
    }

    private fun bindTags() {
        val visible = mutableMapOf<Pair<Int, COrderSymbol>, COrderExport>()
        val global = tagEvents.filter { work.step(); it.site.scopeId == 0 }.groupBy { work.step(); it.symbol }
        val sorted = tagEvents.sortedWith { left, right ->
            work.step()
            val owners = left.site.ownerId.compareTo(right.site.ownerId)
            if (owners == 0) left.site.originalOffset.compareTo(right.site.originalOffset) else owners
        }
        for (event in sorted) {
            work.step()
            var cursor: Int? = event.site.scopeId
            var binding: COrderExport? = null
            if (!event.definition || event.site.scopeId == 0) while (cursor != null && binding == null) {
                work.step(); binding = visible[cursor to event.symbol]; cursor = scopes[cursor].parent
            }
            if (binding == null) {
                binding = event
                visible[event.site.scopeId to event.symbol] = event
            }
            tagBindings[event.site] = binding
            if (event.site.scopeId != 0) {
                if (binding.site.scopeId != 0 && global[event.symbol].orEmpty().isNotEmpty()) {
                    throw IllegalArgumentException("ambiguous generated-C prototype tag dependency in ${event.site.ownerId}: ${event.tagKind} ${(event.symbol as COrderSymbol.Tag).name}")
                }
                if (binding.site.scopeId == 0) use(event.site, event.symbol, COrderNeed.TAG_VISIBLE)
            }
            // References to an enclosing tag do not introduce a second local identity.
            if (event.site.scopeId == 0 || binding === event || event.definition) addExport(event)
        }
    }

    private fun resolve(shape: COrderShape, visiting: MutableSet<String>, depth: Int): Pair<COrderShape, Int> {
        work.step()
        require(depth < 64) { "typedef resolution exceeds depth 64" }
        if (shape is COrderShape.Alias) {
            require(visiting.add(shape.name)) { "unresolved generated-C typedef cycle at ${shape.name}" }
            val cached = shapeCache[shape.name]
            if (cached != null) {
                require(depth + cached.second < 64) { "typedef resolution exceeds depth 64 at ${shape.name}" }
                visiting.remove(shape.name); return cached
            }
            val underlying = aliases[shape.name] ?: return COrderShape.Scalar to 0
            val inner = resolve(underlying, visiting, depth + 1)
            val value = inner.first to inner.second + 1
            visiting.remove(shape.name); shapeCache[shape.name] = value
            return value
        }
        val child = when (shape) {
            is COrderShape.Pointer -> shape.inner
            is COrderShape.Array -> shape.inner
            is COrderShape.Function -> shape.result
            is COrderShape.Atomic -> shape.inner
            else -> return shape to 0
        }
        val (inner, length) = resolve(child, visiting, depth + 1)
        return when (shape) {
            is COrderShape.Pointer -> COrderShape.Pointer(inner)
            is COrderShape.Array -> COrderShape.Array(inner, shape.sized)
            is COrderShape.Function -> COrderShape.Function(inner)
            is COrderShape.Atomic -> COrderShape.Atomic(inner)
            else -> error("terminal shape")
        } to length + 1
    }
    private fun constructors(shape: COrderShape, at: COrderSite, depth: Int) {
        work.step(); require(depth < 64) { "type constructor nesting exceeds 64" }
        when (shape) {
            is COrderShape.Pointer -> constructors(shape.inner, at, depth + 1)
            is COrderShape.Array -> { constructors(shape.inner, at, depth + 1); complete(shape.inner, at, depth + 1) }
            is COrderShape.Atomic -> { constructors(shape.inner, at, depth + 1); complete(shape.inner, at, depth + 1) }
            is COrderShape.Function -> constructors(shape.result, at, depth + 1)
            else -> Unit
        }
    }
    private fun complete(shape: COrderShape, at: COrderSite, depth: Int) {
        work.step(); require(depth < 64) { "type completeness nesting exceeds 64" }
        when (shape) {
            is COrderShape.Alias -> complete(resolve(shape, linkedSetOf(), 0).first, at, depth + 1)
            is COrderShape.Tag -> {
                val binding = tagBindings.getValue(shape.site)
                if (binding.site.scopeId == 0) use(at, COrderSymbol.Tag(shape.name), COrderNeed.COMPLETE_BODY)
                else {
                    val body = exports.firstOrNull { work.step(); it.symbol == binding.symbol && it.definition && it.site.scopeId == binding.site.scopeId }
                    require(body != null && before(body.site.copy(originalOffset = body.availableOffset), at)) {
                        "unresolved generated-C complete body in ${at.ownerId}: ${shape.name}"
                    }
                }
            }
            is COrderShape.Anonymous -> require(shape.site.ownerId != at.ownerId || shape.completed <= at.originalOffset) {
                "unresolved generated-C complete anonymous body in ${at.ownerId}"
            }
            is COrderShape.Array -> complete(shape.inner, at, depth + 1)
            is COrderShape.Atomic -> complete(shape.inner, at, depth + 1)
            else -> Unit
        }
    }
}

private fun String.cOrderSlice(start: Int, end: Int = length, work: COrderWork? = null): String {
    work?.span(end - start)
    return substring(start, end)
}
