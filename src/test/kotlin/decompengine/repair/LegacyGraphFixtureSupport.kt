package decompengine.repair

/** Project a current serialized graph onto the exact versioned field set used by older writers. */
internal fun authoredLegacyGraphFixture(current: String, schema: Int): String {
    require(schema in 1..4)
    val owner = Class.forName("decompengine.repair.ModuleRevisionGraphKt")
    fun invoke(name: String, vararg args: Any): Any = owner.declaredMethods.single { method ->
        method.name == name && method.parameterCount == args.size && method.parameterTypes.indices.all { index ->
            method.parameterTypes[index].isAssignableFrom(args[index].javaClass)
        }
    }.also { it.isAccessible = true }.invoke(null, *args)
    val currentState = invoke("parseGraph", current)
    val stateClass = currentState.javaClass
    val copyDefault = stateClass.declaredMethods.single { it.name == "copy\$default" }
    val propertyCount = copyDefault.parameterCount - 1 - 1 - 1 // receiver, masks, marker
    val maskCount = (propertyCount + 31) / 32
    val arguments = arrayOfNulls<Any>(copyDefault.parameterCount)
    arguments[0] = currentState
    val properties = stateClass.declaredFields.filterNot { java.lang.reflect.Modifier.isStatic(it.modifiers) }
    val schemaProperty = properties.indexOfFirst { it.name == "schemaVersion" }
    check(properties.size == propertyCount && schemaProperty >= 0)
    for (property in 0 until propertyCount) {
        val type = copyDefault.parameterTypes[property + 1]
        arguments[property + 1] = if (property == schemaProperty) schema else when (type) {
                java.lang.Boolean.TYPE -> false
                java.lang.Byte.TYPE -> 0.toByte()
                java.lang.Short.TYPE -> 0.toShort()
                java.lang.Integer.TYPE -> 0
                java.lang.Long.TYPE -> 0L
                java.lang.Float.TYPE -> 0.0f
                java.lang.Double.TYPE -> 0.0
                java.lang.Character.TYPE -> '\u0000'
                else -> null
        }
        if (property != schemaProperty) {
            val maskIndex = 1 + propertyCount + property / 32
            arguments[maskIndex] = (arguments[maskIndex] as? Int ?: 0) or (1 shl (property % 32))
        }
    }
    check(maskCount == copyDefault.parameterCount - propertyCount - 2)
    copyDefault.isAccessible = true
    val legacyState = copyDefault.invoke(null, *arguments)
    val wireType = Class.forName("decompengine.repair.NullRollbackNodeWire")
    val compactWire = wireType.enumConstants.single { it.toString() == "COMPACT" }
    return invoke("renderGraph", legacyState, compactWire).toString()
}

/** Render a parsed mutation with the repository's canonical graph serializer and original null style. */
internal fun canonicalRepairGraphFixture(mutated: String, canonicalSource: String): String {
    val owner = Class.forName("decompengine.repair.ModuleRevisionGraphKt")
    fun invoke(name: String, vararg args: Any): Any = owner.declaredMethods.single { method ->
        method.name == name && method.parameterCount == args.size && method.parameterTypes.indices.all { index ->
            method.parameterTypes[index].isAssignableFrom(args[index].javaClass)
        }
    }.also { it.isAccessible = true }.invoke(null, *args)
    val state = invoke("parseGraph", mutated)
    val parsedSource = invoke("parseCanonicalGraph", canonicalSource.toByteArray(Charsets.UTF_8), "canonical fixture")
    val wire = parsedSource.javaClass.getDeclaredField("nullNodeWire").also { it.isAccessible = true }.get(parsedSource)
    return invoke("renderGraph", state, wire).toString()
}
