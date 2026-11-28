package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.AnnotatedElement
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Tags

/** Compiled test coverage only: this inventory grants no compiler or runtime authority. */
object ContainedModuleCompilationTestInventory {
    private const val TEST = "org.junit.jupiter.api.Test"
    private const val TESTABLE = "org.junit.platform.commons.annotation.Testable"
    private const val LIVE_TAG = "ci-live"
    private const val MAXIMUM_CLASSES = 256
    private const val MAXIMUM_TESTS = 8192
    private val className = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    private val unsupported = setOf(
        "org.junit.jupiter.params.ParameterizedTest", "org.junit.jupiter.api.TestFactory",
        "org.junit.jupiter.api.TestTemplate", "org.junit.jupiter.api.RepeatedTest",
        "org.junit.jupiter.api.Disabled", "org.junit.jupiter.api.Nested",
        "org.junit.jupiter.api.DisplayName", "org.junit.jupiter.api.DisplayNameGeneration",
    )

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "usage: ContainedModuleCompilationTestInventory <selector-file> <fresh output-json under checkout/build>" }
        val checkout = Path.of("").toAbsolutePath().toRealPath()
        val selector = Path.of(arguments[0]).toAbsolutePath().normalize()
        require(selector.startsWith(checkout) && selector.toRealPath() == selector &&
            Files.isRegularFile(selector, LinkOption.NOFOLLOW_LINKS)) { "selector must be a regular checkout file without symbolic links" }
        val bytes = Files.newInputStream(selector).use { it.readNBytes(65537) }
        require(bytes.size <= 65536) { "test selector exceeds its byte bound" }
        val names = bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotBlank() }.toList()
        require(names.size in 1..MAXIMUM_CLASSES && names.toSet().size == names.size && names.all { className.matches(it) }) {
            "test selector must contain unique fully qualified class names, one per line"
        }
        val loader = Thread.currentThread().contextClassLoader
        val tests = names.sorted().flatMap { name -> inspect(Class.forName(name, false, loader)) }
        require(tests.size in 1..MAXIMUM_TESTS && tests.map { it.first to it.second }.toSet().size == tests.size) {
            "compiled live test inventory must be nonempty, bounded, and unique"
        }
        val inventory = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("contained-module-compilation-test-inventory-v1"),
            "classes" to JsonArray(names.sorted().map(::JsonPrimitive)),
            "testCount" to JsonPrimitive(tests.size),
            "tests" to JsonArray(tests.map { (name, method) -> JsonObject(mapOf(
                "class" to JsonPrimitive(name), "method" to JsonPrimitive(method), "reportName" to JsonPrimitive("$method()"),
            )) }),
        ))
        val output = Path.of(arguments[1]).toAbsolutePath().normalize()
        val build = checkout.resolve("build")
        require(Files.isDirectory(build, LinkOption.NOFOLLOW_LINKS) && build.toRealPath() == build &&
            output != build && output.startsWith(build) && !Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            "inventory output must be fresh and belong to checkout/build"
        }
        var ancestor: Path? = output.parent
        while (ancestor != null) {
            val current = ancestor
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) require(current.toRealPath() == current) {
                "inventory output ancestors must not be symbolic links"
            }
            ancestor = current.parent
        }
        val payload = OracleJson.canonicalBytes(inventory, StrictJsonLimits(
            maximumCanonicalBytes = 2 * 1024 * 1024, maximumDepth = 8, maximumNodes = 100_000,
            maximumStringBytes = 4096, maximumTotalStringBytes = 2 * 1024 * 1024,
        ))
        Files.createDirectories(output.parent)
        Files.write(output, payload, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        println("Inventoried ${tests.size} compiled ci-live tests in ${names.size} classes: $output")
    }

    private fun inspect(type: Class<*>): List<Pair<String, String>> {
        require(!type.isInterface && !Modifier.isAbstract(type.modifiers) && type.enclosingClass == null) {
            "selected test class must be concrete and top-level: ${type.name}"
        }
        val classAnnotations = annotations(type)
        rejectUnsupported(classAnnotations, type.name)
        // Inherited/default-interface and nested tests need JUnit discovery, rather than silently
        // pretending that declared methods are the whole selected class.
        fun rejectInherited(parent: Class<*>?) {
            if (parent == null || parent == Any::class.java) return
            require(parent.declaredMethods.none { isTest(annotations(it)) }) { "inherited tests are unsupported: ${type.name}" }
            rejectInherited(parent.superclass)
            parent.interfaces.forEach(::rejectInherited)
        }
        rejectInherited(type.superclass)
        type.interfaces.forEach(::rejectInherited)
        fun rejectNested(parent: Class<*>) {
            parent.declaredClasses.forEach { nested ->
                require(annotations(nested).none { it.annotationClass.java.name == "org.junit.jupiter.api.Nested" }) {
                    "nested tests are unsupported: ${nested.name}"
                }
                rejectNested(nested)
            }
        }
        rejectNested(type)
        val classLive = hasLiveTag(classAnnotations)
        val selected = type.declaredMethods.mapNotNull { method ->
            val methodAnnotations = annotations(method)
            if (!isTest(methodAnnotations) || (!classLive && !hasLiveTag(methodAnnotations))) return@mapNotNull null
            rejectUnsupported(methodAnnotations, "${type.name}.${method.name}")
            require(methodAnnotations.any { it.annotationClass.java.name == TEST } &&
                method.parameterCount == 0 && method.returnType == Void.TYPE && !Modifier.isStatic(method.modifiers) &&
                !Modifier.isPrivate(method.modifiers) && !method.isSynthetic && !method.isBridge &&
                method.name.length in 1..2048 && method.name.none { it.code < 32 || it.code == 127 }) {
                "only ordinary zero-argument JUnit @Test methods with standard report names are supported: ${type.name}.${method.name}"
            }
            type.name to method.name
        }.sortedBy { it.second }
        require(selected.isNotEmpty()) { "selected class has no compiled ci-live tests: ${type.name}" }
        return selected
    }

    private fun isTest(annotations: List<Annotation>): Boolean = annotations.any {
        it.annotationClass.java.name in setOf(TEST, TESTABLE, "org.junit.Test")
    }

    private fun rejectUnsupported(annotations: List<Annotation>, location: String) {
        val found = annotations.map { it.annotationClass.java.name }.filter { it in unsupported }
        require(found.isEmpty()) { "unsupported test annotations at $location: ${found.joinToString()}" }
    }

    private fun hasLiveTag(annotations: List<Annotation>): Boolean = annotations.any {
        (it is Tag && it.value == LIVE_TAG) || (it is Tags && it.value.any { tag -> tag.value == LIVE_TAG })
    }

    /** Include composed JUnit test/tag annotations while bounding annotation graph traversal. */
    private fun annotations(element: AnnotatedElement): List<Annotation> {
        val result = mutableListOf<Annotation>()
        val visited = mutableSetOf<Class<out Annotation>>()
        fun visit(annotation: Annotation) {
            result += annotation
            val type = annotation.annotationClass.java
            require(result.size <= 1024) { "test annotation graph exceeds its bound" }
            if (visited.add(type) && !type.name.startsWith("java.lang.annotation.")) {
                type.declaredAnnotations.forEach(::visit)
            }
        }
        element.annotations.forEach(::visit)
        return result
    }
}
