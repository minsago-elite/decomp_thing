package decompengine.project

/** Existing generated-C declaration normalization; not an ABI recovery assessment. */
internal fun normalizedPrototype(function: RecoveredFunction): String {
    val raw = normalizeGhidraTypes(function.prototype.trim().removeSuffix(";"))
    val name = safeCName(function.name)
    if (name == "main") return "int main(int argc, char **argv)"
    val rawReturn = raw.substringBefore(function.name).trim()
    val decompiledReturn = function.decompiledC?.trimStart()?.substringBefore(function.name)?.trim()?.substringAfterLast('\n')?.trim()
    val returnType = decompiledReturn?.takeIf(::portableReturnType) ?: rawReturn.takeIf(::portableReturnType) ?: "int"
    return "$returnType $name(void)"
}

private fun portableReturnType(value: String): Boolean = value.matches(
    Regex("(void|char|short|int|long|float|double|size_t|u?int(8|16|32|64)_t)(\\s+long|\\s*\\*)*"),
)

internal fun globalDeclaration(global: RecoveredGlobal, external: Boolean): String {
    val type = normalizeGhidraTypes(global.type.trim())
    val name = safeCName(global.name)
    val array = Regex("^(.+)\\[(\\d+)]$").matchEntire(type)
    val declaration = if (array == null) "$type $name" else "${array.groupValues[1]} $name[${array.groupValues[2]}]"
    if (external) return "extern $declaration;"
    val rawInitializer = global.initializer?.trim()?.split(Regex("\\s+"), limit = 2)?.first()
    val aggregate = array != null || !portableReturnType(type.removeSuffix(" *").trim())
    val initializer = when {
        '*' in type -> "0"
        aggregate -> rawInitializer?.takeIf { (it.startsWith('"') && it.endsWith('"')) || (it.startsWith('{') && it.endsWith('}')) } ?: "{0}"
        rawInitializer?.matches(Regex("[0-9a-fA-F]+h")) == true -> "0x${rawInitializer.dropLast(1)}"
        else -> rawInitializer?.takeIf {
        it.matches(Regex("[-+]?(0x[0-9a-fA-F]+|0|[1-9][0-9]*)([uUlLfF]|[uU][lL])?")) ||
            (it.startsWith('"') && it.endsWith('"')) || (it.startsWith('{') && it.endsWith('}'))
        } ?: if (aggregate) "{0}" else "0"
    }
    return "$declaration = $initializer;"
}

private fun normalizeGhidraTypes(value: String): String = value
    .replace(Regex("\\bundefined8\\b"), "uint64_t")
    .replace(Regex("\\bundefined4\\b"), "uint32_t")
    .replace(Regex("\\bundefined2\\b"), "uint16_t")
    .replace(Regex("\\bundefined1\\b|\\bundefined\\b|\\bbyte\\b"), "uint8_t")
    .replace(Regex("\\blonglong\\b"), "long long")
    .replace(Regex("\\bpointer\\b"), "void *")

internal fun safeCName(name: String): String {
    val sanitized = name.replace(Regex("[^A-Za-z0-9_]+"), "_").ifBlank { "recovered" }
    val collision = sanitized in setOf("_init", "_fini", "_start", "stdin", "stdout", "stderr") || sanitized.startsWith("__")
    return when {
        sanitized.first().isDigit() -> "fn_$sanitized"
        collision -> "recovered_$sanitized"
        else -> sanitized
    }
}

