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
) {
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
        return used + "    ${resultDeclaration(name)} = {0};\n    return $name;"
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
    require(kind != GeneratedCTypeKind.FUNCTION) { "global type denotes a function, not an object" }
    require(external || global.initializer != null || kind != GeneratedCTypeKind.INCOMPLETE_ARRAY) {
        "an unsized array requires retained initializer evidence; a zero placeholder would invent its extent"
    }
    val declaration = type.source.substring(0, type.nameOffset).trimEnd() + " " + safeCName(global.name) +
        type.source.substring(type.nameOffset)
    if (external) "extern $declaration;"
    else {
        // Only absent evidence gets a zero placeholder. Retained initializer expressions are
        // compiler checked; an unfamiliar value must not silently become zero.
        val initializer = global.initializer?.let(::retainedInitializer) ?: "{0}"
        "$declaration = $initializer;"
    }
}

internal enum class GeneratedCTypeKind { VOID, INTEGER, POINTER, ARRAY, INCOMPLETE_ARRAY, FUNCTION, OTHER, UNKNOWN }

/** Resolves only declaration shapes needed by generated code; the compiler still validates C types. */
internal class GeneratedCDeclarationContext(types: List<RecoveredType>) {
    private val aliases = linkedMapOf<String, CDeclaration>()
    private data class ResolvedType(val kind: GeneratedCTypeKind, val resolutionDepth: Int = 0)
    private val resolved = hashMapOf<String, ResolvedType>()

    init {
        var characters = 0L
        for (type in types) declarationFor(type.id) {
            characters += type.declaration.length.toLong()
            require(type.declaration.length <= 1024 * 1024 && characters <= 64L * 1024 * 1024) {
                "typedef context exceeds its source bounds"
            }
            require(cDeclarationTokens(type.declaration).none { it.text == "#" }) {
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

    private fun resolve(
        specifiers: List<String>,
        derived: List<CDerived>,
        atomicType: CDeclaration?,
        visiting: MutableSet<String>,
        depth: Int,
    ): ResolvedType {
        // Use-site operators precede alias operators: an A* stays a pointer even if A is int[].
        when (val outer = derived.firstOrNull()) {
            CDerived.Pointer -> return ResolvedType(GeneratedCTypeKind.POINTER)
            is CDerived.Array -> return ResolvedType(if (outer.hasBound) GeneratedCTypeKind.ARRAY else GeneratedCTypeKind.INCOMPLETE_ARRAY)
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
            return ResolvedType(kind, inner.resolutionDepth + 1)
        }
        if (base == listOf("void")) return ResolvedType(GeneratedCTypeKind.VOID).withAtomicQualifier(specifiers)
        if (base.isNotEmpty() && base.all { it in integerSpecifiers }) return ResolvedType(GeneratedCTypeKind.INTEGER)
        if (base.firstOrNull() == "enum") return ResolvedType(GeneratedCTypeKind.INTEGER)
        if (base.firstOrNull() in setOf("struct", "union") || base.any { it in setOf("float", "double", "_Complex") }) {
            return ResolvedType(GeneratedCTypeKind.OTHER)
        }
        val name = base.singleOrNull() ?: return ResolvedType(GeneratedCTypeKind.UNKNOWN)
        val alias = aliases[name] ?: return ResolvedType(if (name in standardIntegerAliases) GeneratedCTypeKind.INTEGER else GeneratedCTypeKind.UNKNOWN)
        resolved[name]?.let {
            require(depth + it.resolutionDepth <= 64) { "typedef resolution exceeds depth 64 at $name" }
            return it.withAtomicQualifier(specifiers)
        }
        require(depth < 64 && visiting.add(name)) { "cyclic typedef or typedef resolution exceeds depth 64 at $name" }
        val result = resolve(alias.specifiers, alias.derived, alias.atomicType, visiting, depth + 1)
            .let { ResolvedType(it.kind, it.resolutionDepth + 1) }
        visiting.remove(name)
        resolved[name] = result
        return result.withAtomicQualifier(specifiers)
    }

    // A use-site qualifier changes this result, never the cached unqualified alias shape.
    private fun ResolvedType.withAtomicQualifier(specifiers: List<String>): ResolvedType =
        if (kind == GeneratedCTypeKind.VOID && "_Atomic" in specifiers) copy(kind = GeneratedCTypeKind.OTHER) else this

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

private fun splitCTypeSource(source: String, separator: String): List<String> {
    val tokens = cDeclarationTokens(source)
    val stack = mutableListOf<String>()
    val parts = mutableListOf<String>()
    var start = 0
    for (token in tokens) {
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
                parts += source.substring(start, token.start)
                start = token.end
            }
        }
    }
    require(stack.isEmpty()) { "unclosed type declaration" }
    val tail = source.substring(start)
    if (cDeclarationTokens(tail).isNotEmpty()) parts += tail
    return parts.filter { cDeclarationTokens(it).isNotEmpty() }
}

private fun aliasParsingView(source: String): String {
    val tokens = cDeclarationTokens(source)
    val edits = mutableListOf<Triple<Int, Int, String>>()
    var index = 0
    while (index < tokens.size) {
        if (tokens[index].text in setOf("struct", "union", "enum")) {
            val aggregateStart = index
            var body = index + 1
            if (tokens.getOrNull(body)?.text != "{") body++
            if (tokens.getOrNull(body)?.text == "{") {
                var nesting = 1
                var end = body + 1
                while (end < tokens.size && nesting > 0) {
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
    return edits.asReversed().fold(source) { text, (start, end, replacement) -> text.replaceRange(start, end, replacement) }
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
    val start = skipEmptyCStatements(tokens, 0)
    val size = when {
        hasCTokens(tokens, start, listOf("return", ";")) -> 2
        hasCTokens(tokens, start, listOf("return", "0", ";")) -> 3
        else -> return@runCatching false
    }
    skipEmptyCStatements(tokens, start + size) == tokens.size
}.getOrDefault(false)

private fun normalizedPlaceholderBody(body: String): List<String>? {
    val tokens = cDeclarationTokens(body)
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
    if (!hasCTokens(tokens, initializer, listOf("=", "{", "0", "}", ";"))) return null
    val returnStart = skipEmptyCStatements(tokens, initializer + 5)
    if (!hasCTokens(tokens, returnStart, listOf("return", name.text, ";")) ||
        skipEmptyCStatements(tokens, returnStart + 3) != tokens.size) return null
    // Replace only the declared identifier: the same spelling may also be a struct tag,
    // typedef name, or a parameter inside a function-pointer declarator.
    return cDeclarationTokens(declaration.source).map {
        if (it.start == name.start && it.end == name.end) "<result>" else it.text
    }
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
    data object Pointer : CDerived
    data class Array(val hasBound: Boolean) : CDerived
    data class Function(
        val start: Int,
        val end: Int,
        val parameters: List<CDeclaration>,
        val explicitVoid: Boolean,
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
private class CDeclarationParser(raw: String, private val symbolicName: String? = null, private val depth: Int = 0) {
    private var trailingLineComment = false
    private val tokens = cDeclarationTokens(raw, symbolicName) { trailingLineComment = true }
    private val raw = if (trailingLineComment) "$raw\n" else raw
    private var cursor = 0

    fun parse(allowAbstract: Boolean = false, allowSemicolon: Boolean = true): CDeclaration {
        require(depth < 64) { "declarator nesting exceeds 64" }
        require(tokens.isNotEmpty()) { "empty declaration" }
        val specifiers = mutableListOf<String>()
        val storageSpecifiers = mutableListOf<CToken>()
        var atomicType: CDeclaration? = null
        var hasType = false
        while (cursor < tokens.size) {
            val token = tokens[cursor].text
            when {
                token == "_Atomic" && tokens.getOrNull(cursor + 1)?.text == "(" -> {
                    require(atomicType == null) { "multiple atomic type specifiers are unsupported" }
                    val start = tokens[cursor].start
                    val end = matchingCToken(tokens, cursor + 1)
                    atomicType = CDeclarationParser(raw.substring(tokens[cursor + 1].end, tokens[end].start), depth = depth + 1)
                        .parse(allowAbstract = true, allowSemicolon = false)
                    require(atomicType.name == null && atomicType.storageSpecifiers.isEmpty()) {
                        "an atomic type-name must be abstract and have no storage specifiers"
                    }
                    specifiers += raw.substring(start, tokens[end].end)
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
        require(nesting < 64) { "declarator nesting exceeds 64" }
        var pointers = 0
        while (tokens.getOrNull(cursor)?.text == "*") {
            pointers++
            cursor++
            while (tokens.getOrNull(cursor)?.text in qualifiers) cursor++
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
            when (tokens[cursor].text) {
                "(" -> {
                    val end = matchingCToken(tokens, cursor)
                    derived += parameterList(raw, tokens, cursor, end, depth + 1)
                    cursor = end + 1
                }
                "[" -> {
                    val end = matchingCToken(tokens, cursor)
                    derived += CDerived.Array(hasBound = end > cursor + 1)
                    cursor = end + 1
                }
                else -> break
            }
        }
        repeat(pointers) { derived += CDerived.Pointer }
        return Declarator(name, nameOffset, derived)
    }

    companion object {
        private val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
        private val qualifiers = setOf("const", "volatile", "restrict", "_Atomic")
        private val builtinTypes = setOf("void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "_Complex")

        fun parameterList(source: String, tokens: List<CToken>, start: Int, end: Int, depth: Int = 0): CDerived.Function {
            if (end == start + 2 && tokens[start + 1].text == "void") {
                return CDerived.Function(tokens[start].start, tokens[end].end, emptyList(), true)
            }
            val parameters = mutableListOf<CDeclaration>()
            var cursor = start + 1
            while (cursor < end) {
                val first = cursor
                while (cursor < end && tokens[cursor].text != ",") {
                    cursor = if (tokens[cursor].text in setOf("(", "[")) matchingCToken(tokens, cursor) + 1 else cursor + 1
                }
                require(cursor > first) { "empty parameter declaration" }
                if (cursor == first + 1 && tokens[first].text == "...") {
                    require(parameters.isNotEmpty() && cursor == end) { "ellipsis requires preceding parameters and must be last" }
                } else {
                    val parameter = CDeclarationParser(source.substring(tokens[first].start, tokens[cursor - 1].end), depth = depth)
                        .parse(allowAbstract = true, allowSemicolon = false)
                    require(parameter.specifiers != listOf("void") || parameter.derived.isNotEmpty()) { "void must be the only parameter" }
                    parameters += parameter
                }
                if (cursor < end) {
                    cursor++
                    require(cursor < end) { "trailing parameter comma" }
                }
            }
            return CDerived.Function(tokens[start].start, tokens[end].end, parameters, false)
        }
    }
}

private val cStorageSpecifiers = setOf("extern", "static", "register", "auto", "inline", "_Noreturn", "_Thread_local", "typedef")

/** Lexical offsets let rendering retain original whitespace, qualifiers, and comments. */
private fun cDeclarationTokens(
    source: String,
    symbolicName: String? = null,
    skipDirectives: Boolean = false,
    onTrailingLineComment: () -> Unit = {},
): List<CToken> {
    val result = mutableListOf<CToken>()
    var cursor = 0
    while (cursor < source.length) {
        val start = cursor
        when {
            source[cursor].isWhitespace() -> cursor++
            skipDirectives && source[cursor] == '#' && source.substring(source.lastIndexOf('\n', cursor) + 1, cursor).isBlank() -> {
                cursor = source.indexOf('\n', cursor).let { if (it < 0) source.length else it }
            }
            source.startsWith("//", cursor) -> {
                val newline = source.indexOfAny(charArrayOf('\r', '\n'), cursor)
                val end = if (newline < 0) source.length else newline
                var last = end - 1
                while (last > cursor && source[last].isWhitespace()) last--
                // Translation splices escaped physical newlines before removing comments.
                // Even a blank following line triggers -Wcomment under the strict profile.
                val escaped = source[last] == '\\' || (last >= 2 && source.regionMatches(last - 2, "??/", 0, 3))
                require(!escaped) { "a line comment ending in backslash cannot safely precede generated C syntax" }
                cursor = if (newline < 0) { onTrailingLineComment(); source.length } else newline
            }
            source.startsWith("/*", cursor) -> {
                val end = source.indexOf("*/", cursor + 2)
                require(end >= 0) { "unclosed comment" }
                cursor = end + 2
            }
            source[cursor] == '"' || source[cursor] == '\'' -> {
                val quote = source[cursor++]
                while (cursor < source.length && source[cursor] != quote) {
                    if (source[cursor] == '\\') cursor++
                    cursor++
                }
                require(cursor < source.length) { "unclosed literal" }
                cursor++
                result += CToken(source.substring(start, cursor), start, cursor)
            }
            symbolicName?.isNotEmpty() == true && source.startsWith(symbolicName, cursor) &&
                source.getOrNull(cursor + symbolicName.length)?.let { !it.isLetterOrDigit() && it != '_' } != false -> {
                cursor += symbolicName.length
                result += CToken(symbolicName, start, cursor)
            }
            source[cursor].isLetterOrDigit() || source[cursor] == '_' -> {
                do { cursor++ } while (cursor < source.length && (source[cursor].isLetterOrDigit() || source[cursor] == '_'))
                result += CToken(source.substring(start, cursor), start, cursor)
            }
            source.startsWith("...", cursor) -> {
                cursor += 3
                result += CToken("...", start, cursor)
            }
            else -> { cursor++; result += CToken(source.substring(start, cursor), start, cursor) }
        }
    }
    return result
}

private fun matchingCToken(tokens: List<CToken>, start: Int): Int {
    val stack = mutableListOf<String>()
    for (index in start until tokens.size) {
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
