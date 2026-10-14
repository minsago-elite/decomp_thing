package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.jar.JarFile
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LlvmBehaviorNativeHelperDeploymentReferenceV1Test {
    @Test fun `class directory and configured reference cannot create installed authority`() {
        assertFailsWith<IllegalArgumentException> { LlvmBehaviorNativeHelperDeploymentReferenceV1.open() }
        val property = "decompengine.oracle.behavior.nativeHelperReference"
        val prior = System.getProperty(property)
        try {
            System.setProperty(property, "")
            assertFailsWith<IllegalArgumentException> { LlvmBehaviorNativeHelperDeploymentReferenceV1.open() }
        } finally { if (prior == null) System.clearProperty(property) else System.setProperty(property, prior) }
    }

    @Test fun `rewritten compilation and source commitments fail closed even with a recomputed closure`() {
        val output = Path.of(checkNotNull(System.getProperty("decompengine.oracle.behavior.nativeHelperBuildDirectory")))
        val bytes = Files.readAllBytes(output.resolve(NATIVE_HELPER_REFERENCE_NAME))
        val source = Files.readAllBytes(output.resolve(NATIVE_HELPER_SOURCE_NAME))
        val build = Files.readAllBytes(output.resolve(NATIVE_HELPER_BUILD_NAME))
        val root = OracleJson.parseCanonical(bytes) as JsonObject
        val compilation = root.getValue("compilation") as JsonObject
        fun rewritten(document: JsonObject): ByteArray {
            val unsigned = JsonObject(document - "closureSha256")
            return OracleJson.canonicalBytes(JsonObject(unsigned + ("closureSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))))))
        }
        val environment = compilation.getValue("environment") as JsonObject
        val drift = JsonObject(root + ("compilation" to JsonObject(compilation + ("environment" to JsonObject(environment +
            ("CPATH" to JsonPrimitive("/foreign")))))))
        assertFailsWith<IllegalArgumentException> { parseNativeHelperReference(rewritten(drift), source, build) }
        val changed = source.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<IllegalArgumentException> { parseNativeHelperReference(rewritten(JsonObject(root +
            ("source" to helperFileRecord(NATIVE_HELPER_SOURCE_NAME, changed)))), changed, build) }
    }

    @Test fun `real installed JAR authenticates helper source build and substitution refusals`() = withNativeHelperTestDirectory { work ->
        val installed = Path.of(checkNotNull(System.getProperty("decompengine.oracle.behavior.nativeHelperInstalledRoot")))
        val lib = installed.resolve("lib")
        val jars = Files.list(lib).use { entries -> entries.filter { it.fileName.toString().endsWith(".jar") }.toList() }
        val application = jars.single { path -> JarFile(path.toFile(), false).use { jar ->
            jar.getJarEntry("decompengine/oracle/behavior/LlvmBehaviorNativeHelperDeploymentReferenceV1.class") != null } }
        val source = Files.readAllBytes(nativeHelperTestSource())
        JarFile(application.toFile(), false).use { jar ->
            val entries = jar.entries().asSequence().toList()
            val entry = entries.single { it.name == NATIVE_HELPER_RESOURCE_ROOT + NATIVE_HELPER_SOURCE_NAME }
            assertEquals(source.toList(), jar.getInputStream(entry).use { it.readAllBytes() }.toList())
            listOf(NATIVE_HELPER_BUILD_NAME, NATIVE_HELPER_REFERENCE_NAME).forEach { name ->
                val resource = entries.single { it.name == NATIVE_HELPER_RESOURCE_ROOT + name }
                assertEquals(Files.readAllBytes(installed.resolve("libexec/$name")).toList(),
                    jar.getInputStream(resource).use { it.readAllBytes() }.toList())
            }
        }
        val relocated = Files.createDirectory(work.resolve("install"))
        val relocatedLib = Files.createDirectory(relocated.resolve("lib"))
        val relocatedExec = Files.createDirectory(relocated.resolve("libexec"))
        val selected = Files.copy(application, relocatedLib.resolve(application.fileName), StandardCopyOption.COPY_ATTRIBUTES)
        NATIVE_HELPER_INSTALLED_NAMES.forEach { name ->
            Files.copy(installed.resolve("libexec/$name"), relocatedExec.resolve(name), StandardCopyOption.COPY_ATTRIBUTES)
        }
        val testLocation = Path.of(LlvmBehaviorNativeHelperInstalledProbe::class.java.protectionDomain.codeSource.location.toURI())
        val classpath = (listOf(testLocation, selected) + jars.filter { it != application }).joinToString(java.io.File.pathSeparator)
        fun probe(extra: String? = null, classpathPrefix: Path? = null): Int {
            val command = mutableListOf(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-XX:-UsePerfData",
                "-Djava.io.tmpdir=$work", "-Djna.tmpdir=$work", "-Duser.home=$work", "-Djna.nosys=true", "-Djna.nounpack=true",
                "-Djna.boot.library.path=${nativeHelperTestNativeDirectory()}")
            extra?.let(command::add)
            val selectedClasspath = classpathPrefix?.let { "$it${java.io.File.pathSeparator}$classpath" } ?: classpath
            command += listOf("-cp", selectedClasspath, LlvmBehaviorNativeHelperInstalledProbe::class.java.name)
            val builder = ProcessBuilder(command).redirectErrorStream(true).redirectOutput(work.resolve("installed.log").toFile())
            builder.environment().clear()
            builder.environment().putAll(mapOf("HOME" to work.toString(), "TMPDIR" to work.toString(), "PATH" to "/usr/bin:/bin", "LANG" to "C"))
            val child = builder.start()
            try {
                assertTrue(child.waitFor(30, java.util.concurrent.TimeUnit.SECONDS), "installed helper probe exceeded its deadline")
                return child.exitValue()
            } finally { if (child.isAlive) { child.destroyForcibly(); child.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) } }
        }
        assertEquals(0, probe(), Files.readString(work.resolve("installed.log")))
        assertTrue(probe("-Ddecompengine.oracle.behavior.nativeHelperReference=") != 0)
        val shadow = work.resolve("shadow.jar")
        JarOutputStream(Files.newOutputStream(shadow)).use { jar ->
            jar.putNextEntry(JarEntry(NATIVE_HELPER_RESOURCE_ROOT + NATIVE_HELPER_SOURCE_NAME))
            jar.write("foreign source".encodeToByteArray())
            jar.closeEntry()
        }
        assertTrue(probe(classpathPrefix = shadow) != 0, "shadowed resource bypassed own-JAR selection")
        val duplicate = work.resolve("duplicate.jar")
        ZipArchiveOutputStream(duplicate).use { destination ->
            JarFile(application.toFile(), false).use { jar ->
                jar.entries().asSequence().forEach { entry ->
                    destination.putArchiveEntry(ZipArchiveEntry(entry.name))
                    if (!entry.isDirectory) jar.getInputStream(entry).use { it.copyTo(destination) }
                    destination.closeArchiveEntry()
                }
                destination.putArchiveEntry(ZipArchiveEntry(NATIVE_HELPER_RESOURCE_ROOT + NATIVE_HELPER_SOURCE_NAME))
                destination.write(source)
                destination.closeArchiveEntry()
            }
        }
        Files.copy(duplicate, selected, StandardCopyOption.REPLACE_EXISTING)
        assertTrue(probe() != 0, "duplicate source resource bypassed own-JAR selection")
        Files.copy(application, selected, StandardCopyOption.REPLACE_EXISTING)
        val helper = relocatedExec.resolve(NATIVE_HELPER_NAME)
        val original = Files.readAllBytes(helper)
        val mutation = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        Files.write(helper, mutation)
        Files.writeString(relocatedExec.resolve(NATIVE_HELPER_CHECKSUM_NAME), "${OracleArtifacts.sha256(mutation)}  $NATIVE_HELPER_NAME\n")
        assertTrue(probe() != 0, "rewritten helper/checksum bypassed own-JAR reference")
        Files.write(helper, original)
        Files.copy(installed.resolve("libexec/$NATIVE_HELPER_CHECKSUM_NAME"), relocatedExec.resolve(NATIVE_HELPER_CHECKSUM_NAME), StandardCopyOption.REPLACE_EXISTING)
        Files.writeString(relocatedExec.resolve(NATIVE_HELPER_BUILD_NAME), "{}")
        assertTrue(probe() != 0, "rewritten build record bypassed own-JAR reference")
        assertTrue(Files.isRegularFile(selected, LinkOption.NOFOLLOW_LINKS))
    }
}

/** Child classpath contains real installed production classes; no main class-directory fallback. */
object LlvmBehaviorNativeHelperInstalledProbe {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.isEmpty())
        LlvmBehaviorNativeHelperDeploymentReferenceV1.open().use {
            it.requireCurrent()
            check(!it.compilerToolchainClosureAuthenticated && !it.runtimeProfilePinned && !it.referencePinned &&
                !it.startAuthorized && !it.containmentAuthority && !it.scoringAuthority && !it.releaseEligible)
            println("${it.helperSha256} ${it.sourceSha256} ${it.buildRecordSha256} ${it.referenceSha256}")
        }
    }
}
