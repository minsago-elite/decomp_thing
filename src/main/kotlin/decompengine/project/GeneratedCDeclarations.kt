package decompengine.project

/** Preserve declared C types. Only the function declarator's identifier may be renamed. */
internal fun normalizedPrototype(function: RecoveredFunction): String = recoveredDeclaration(function).prototype

internal class GeneratedCFunctionDeclaration(
    val prototype: String,
    val parameterNames: List<String>,
    val hasUnnamedParameters: Boolean,
    val explicitNoParameters: Boolean,
    val hasInternalLinkage: Boolean,
    private val returnsVoid: Boolean,
    private val resultDeclaration: (String) -> String,
) {
    fun placeholderBody(): String {
        require(!hasUnnamedParameters) { "an evidence placeholder requires named parameters" }
        val used = unusedParameterReferences(parameterNames)
        if (returnsVoid) return used + "    return;"
        // A declaration, rather than a guessed cast to int, also supports pointers, structs,
        // and explicitly declared typedefs. The compiler still decides whether the type is valid.
        val identifiers = cDeclarationTokens(prototype).mapTo(hashSetOf()) { it.text }
        val name = generateSequence("decomp_placeholder_result") { "${it}_" }.first { it !in identifiers }
        return used + "    ${resultDeclaration(name)} = {0};\n    return $name;"
    }

    fun entryCall(name: String): String {
        require(explicitNoParameters) { "a synthesized entry call requires an explicit (void) parameter list" }
        return if (returnsVoid) "$name();\n    return 0;" else "return $name();"
    }
}

internal fun recoveredDeclaration(function: RecoveredFunction): GeneratedCFunctionDeclaration = declarationFor(function.id) {
    val declaration = CDeclarationParser(function.prototype.trim(), function.name).parse()
    require("typedef" !in declaration.specifiers) { "prototype declares a typedef, not a function" }
    require(declaration.name?.text == function.name) { "prototype must declare ${function.name}" }
    val parameters = declaration.derived.firstOrNull() as? CDerived.Function
        ?: error("prototype must declare a function, not a pointer or object")
    val identifier = requireNotNull(declaration.name)
    val source = declaration.source
    val prototype = source.replaceRange(identifier.start, identifier.end, safeCName(function.name))
    GeneratedCFunctionDeclaration(
        prototype = prototype,
        parameterNames = parameters.parameters.mapNotNull { it.name?.text },
        hasUnnamedParameters = parameters.parameters.any { it.name == null },
        explicitNoParameters = parameters.explicitVoid,
        hasInternalLinkage = "static" in declaration.specifiers,
        returnsVoid = declaration.specifiers.filterNot { it in cStorageSpecifiers } == listOf("void") && declaration.derived.size == 1,
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

internal fun globalDeclaration(global: RecoveredGlobal, external: Boolean): String = declarationFor(global.id) {
    val type = CDeclarationParser(global.type.trim()).parse(allowAbstract = true)
    require(type.name == null) { "global type must be an abstract declarator without an object name" }
    require(type.derived.firstOrNull() !is CDerived.Function) { "global type denotes a function, not an object" }
    require(external || global.initializer != null || (type.derived.firstOrNull() as? CDerived.Array)?.hasBound != false) {
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

/** Match our own placeholder without treating a typed zero temporary as recovered behavior. */
internal fun isGeneratedCPlaceholderBody(function: RecoveredFunction, body: String): Boolean = runCatching {
    cDeclarationTokens(body).map { it.text } ==
        cDeclarationTokens(recoveredDeclaration(function).placeholderBody()).map { it.text }
}.getOrDefault(false)

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

private data class CToken(val text: String, val start: Int, val end: Int)
private sealed interface CDerived {
    data object Pointer : CDerived
    data class Array(val hasBound: Boolean) : CDerived
    data class Function(
        val start: Int,
        val end: Int,
        val parameters: List<CDeclaration>,
        val explicitVoid: Boolean,
    ) : CDerived
}
private data class CDeclaration(
    val source: String,
    val specifiers: List<String>,
    val storageSpecifiers: List<CToken>,
    val name: CToken?,
    val nameOffset: Int,
    /** Declarator operations ordered from the identifier outward. */
    val derived: List<CDerived>,
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
        var hasType = false
        while (cursor < tokens.size) {
            val token = tokens[cursor].text
            when {
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
        val declarator = declarator(allowAbstract, 0)
        val semicolon = tokens.getOrNull(cursor)?.takeIf { it.text == ";" }
        require(allowSemicolon || semicolon == null) { "semicolon is not allowed in a parameter" }
        if (semicolon != null) cursor++
        require(cursor == tokens.size) { "unexpected token ${tokens[cursor].text}" }
        val source = if (semicolon == null) raw else raw.removeRange(semicolon.start, semicolon.end)
        return CDeclaration(source, specifiers, storageSpecifiers, declarator.name, declarator.nameOffset, declarator.derived)
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

private val cStorageSpecifiers = setOf("extern", "static", "register", "auto", "inline", "_Noreturn", "_Thread_local")

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
            source.startsWith("//", cursor) -> cursor = source.indexOf('\n', cursor).let {
                if (it < 0) { onTrailingLineComment(); source.length } else it
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
