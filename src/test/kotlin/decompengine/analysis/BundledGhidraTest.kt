package decompengine.analysis

import decompengine.project.sha256
import decompengine.project.RecoveredCallSitesTest
import decompengine.oracle.gcc.GccCompilerEngineProfiles
import decompengine.oracle.gcc.authenticateGhidraInstallation
import decompengine.oracle.gcc.GccBundledGhidraDeploymentReference
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.api.parallel.Resources

@ResourceLock(Resources.SYSTEM_PROPERTIES)
class BundledGhidraTest {
    @Test
    fun `installed native collector source and complete compiled closure match the production reference`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true" || System.getenv("RUN_REAL_GHIDRA_NATIVE_CALLS") == "true",
            "installed native collector packaging check is opt-in")
        val repository = Path.of(System.getProperty("user.dir")).toRealPath()
        val evidenceParent = repository.resolve("build/native-call-packaging-tests")
        Files.createDirectories(evidenceParent)
        val work = Files.createTempDirectory(evidenceParent, "installed-native-")
        try {
            val processHome = Files.createDirectory(work.resolve("home"))
            val temporary = Files.createDirectory(work.resolve("tmp"))
            val cache = Files.createDirectory(work.resolve("cache"))
            val sourceName = "ghidra-bridge/src/main/java/ExportNativeCallsV1.java"
            val source = repository.resolve(sourceName).toRealPath()
            assertFalse(Files.exists(repository.resolve("src/main/resources/ghidra_scripts/ExportNativeCallsV1.java"), LinkOption.NOFOLLOW_LINKS),
                "native collector resource must be generated from its compiled Java source")
            val inventoryLog = work.resolve("tracked-source.log")
            val inventory = ProcessBuilder("git", "ls-files", "--", "*ExportNativeCallsV1.java")
                .directory(repository.toFile()).apply {
                    environment()["HOME"] = processHome.toString()
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["XDG_CACHE_HOME"] = cache.toString()
                    environment()["GIT_CONFIG_NOSYSTEM"] = "1"
                    redirectErrorStream(true)
                    redirectOutput(inventoryLog.toFile())
                }.start()
            try {
                assertTrue(inventory.waitFor(10, TimeUnit.SECONDS), "tracked collector source inventory timed out")
                assertEquals(0, inventory.exitValue(), inventoryLog.readText())
                assertEquals(listOf(sourceName), inventoryLog.readText().lineSequence().filter(String::isNotBlank).toList(),
                    "the collector must have one tracked source and no tracked resource copy")
            } finally {
                if (inventory.isAlive) inventory.destroyForcibly()
                assertTrue(inventory.waitFor(5, TimeUnit.SECONDS), "tracked source inventory could not be reaped")
            }
            val installed = repository.resolve("build/install/llm_bin_patch").toRealPath()
            val libraries = Files.list(installed.resolve("lib")).use { paths -> paths.filter {
                Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && it.fileName.toString().endsWith(".jar")
            }.sorted().limit(513).toList() }
            assertTrue(libraries.size in 1..512)
            val application = libraries.single { path -> JarFile(path.toFile(), false).use {
                it.getJarEntry("decompengine/oracle/gcc/GccBundledGhidraDeploymentReference.class") != null
            } }
            val tests = Path.of(BundledGhidraInstalledNativeCollectorProbe::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
            assertTrue(Files.isDirectory(tests), "installed probe must come from the test class directory")
            val compiledClasses = repository.resolve("ghidra-bridge/build/classes/java/main").toRealPath()
            val log = work.resolve("installed-native-reference.log")
            val command = listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "-Duser.home=$processHome", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary", "-XX:-UsePerfData",
                "-Ddecompengine.oracle.nativeLibraryDirectory=${installed.resolve("libexec/oracle-native")}",
                "-cp", (listOf(tests) + libraries).joinToString(File.pathSeparator),
                BundledGhidraInstalledNativeCollectorProbe::class.java.name,
                application.toString(), installed.resolve("libexec/ghidra").toString(), source.toString(), compiledClasses.toString())
            val process = ProcessBuilder(command).directory(work.toFile()).apply {
                for (name in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "GHIDRA_HOME")) environment().remove(name)
                environment()["HOME"] = processHome.toString()
                environment()["TMPDIR"] = temporary.toString()
                environment()["XDG_CONFIG_HOME"] = processHome.toString()
                environment()["XDG_DATA_HOME"] = processHome.toString()
                environment()["XDG_CACHE_HOME"] = cache.toString()
                redirectErrorStream(true)
                redirectOutput(log.toFile())
            }.start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS), "installed native reference check timed out")
                assertTrue(Files.size(log) <= 64 * 1024, "installed native reference diagnostics exceeded the bound")
                val diagnostic = log.readText()
                assertEquals(0, process.exitValue(), diagnostic)
                assertTrue(diagnostic.lineSequence().any { it.startsWith("installed-native-collector-reference-verified:") }, diagnostic)
            } finally {
                if (process.isAlive) process.destroyForcibly()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "installed native reference check could not be reaped")
                process.outputStream.close()
                process.inputStream.close()
                process.errorStream.close()
            }
        } finally {
            Files.walk(work).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    @Test
    fun `shared worker command rejects empty duplicate and ambiguous classpaths`() {
        val java = Path.of("/runtime/bin/java")
        val release = Path.of("/application/ghidra")
        val bridge = Path.of("/application/bridge.jar")
        for (entries in listOf(emptyList(), listOf(bridge, bridge), listOf(Path.of("/application/part:other.jar")))) {
            assertFailsWith<IllegalArgumentException> { GhidraWorkerCommand.prefix(java, release, entries) }
        }
        val prefix = GhidraWorkerCommand.prefix(java, release, listOf(bridge))
        assertFalse(prefix.any { it.startsWith("-Duser.home=") || it.startsWith("-Djava.io.tmpdir=") || it.startsWith("-Djna.tmpdir=") })
        assertFalse("-XX:-UsePerfData" in prefix, "contained runtimes own their exact shared-prefix policy")
    }

    @Test
    fun `ordinary worker forwards only normalized parent directories without changing its resource policy`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        val workingDirectory = Path.of("").toAbsolutePath().normalize()
        val home = root.resolve("parent home = kept").createDirectories()
        val temporary = root.resolve("parent temp").createDirectories()
        val nativeTemporary = root.resolve("native temp").createDirectories()
        withParentDirectoryProperties(mapOf(
            "user.home" to workingDirectory.relativize(home).toString(),
            "java.io.tmpdir" to temporary.toString(),
            "jna.tmpdir" to workingDirectory.relativize(nativeTemporary).toString(),
            "decompengine.unrelated.parent.property" to "not-forwarded",
        )) {
            val command = bundle.probeCommand()
            assertEquals(listOf(
                "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$nativeTemporary",
            ), command.filter { it.startsWith("-Duser.home=") || it.startsWith("-Djava.io.tmpdir=") || it.startsWith("-Djna.tmpdir=") })
            assertEquals(1, command.count { it == "-XX:-UsePerfData" })
            assertTrue("-Xmx2G" in command)
            assertTrue("-Xshare:off" in command)
            assertFalse(command.any { it.contains("decompengine.unrelated.parent.property") || it.contains("not-forwarded") })
            assertEquals("probe", command.last())
        }
    }

    @Test
    fun `ordinary worker does not invent an absent JNA directory`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        withParentDirectoryProperties(mapOf("jna.tmpdir" to null)) {
            assertFalse(bundle.probeCommand().any { it.startsWith("-Djna.tmpdir=") })
        }
    }

    @Test
    fun `all call site regressions have JUnit discoverable void signatures`() {
        val methods = RecoveredCallSitesTest::class.java.declaredMethods.filter {
            it.isAnnotationPresent(org.junit.jupiter.api.Test::class.java)
        }
        assertEquals(7, methods.size)
        methods.forEach { assertEquals(Void.TYPE, it.returnType, it.name) }
    }

    @Test
    fun `worker command links bundled libraries and preserves separated script arguments`() = withFixture { root ->
        val bundle = fixture(root.resolve("app bundle"))
        val input = root.resolve("input with spaces")
        val invocation = GhidraInvocation(root.resolve("project"), "fixture", input, root.resolve("scripts"), listOf(
            GhidraPostScript("Export.java", listOf("argument with spaces", "--not-a-worker-option")),
        ))
        val command = bundle.analysisCommand(invocation)
        assertTrue(BundledGhidra.WORKER_CLASS in command)
        assertTrue(command[command.indexOf("-cp") + 1].contains("decomp-ghidra-bridge.jar"))
        assertTrue(command[command.indexOf("-cp") + 1].contains("Base.jar"))
        assertFalse(command.any { it.contains("analyzeHeadless") || it.contains("AnalyzeHeadless") })
        assertEquals(listOf("Export.java", "2", "argument with spaces", "--not-a-worker-option"), command.takeLast(4))
        assertTrue(input.toAbsolutePath().toString() in command)
    }

    @Test
    fun `missing corrupt extra and linked bundle files fail before worker launch`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        bundle.verify()
        val library = bundle.release.resolve("Ghidra/Features/Base/lib/Base.jar")
        library.writeText("modified")
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        library.writeText("library fixture")
        val extra = bundle.root.resolve("extra.jar").also { it.writeText("unindexed") }
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        Files.delete(extra)
        Files.delete(library)
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        Files.createSymbolicLink(library, bundle.root.resolve("decomp-ghidra-bridge.jar"))
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
    }

    @Test
    fun `invalid duplicate and escaping checksum records are rejected`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        val manifest = bundle.root.resolve("bundle.sha256")
        val valid = manifest.readText()
        listOf("invalid\n", valid + valid, "${"0".repeat(64)}  ../escape\n").forEach { invalid ->
            manifest.writeText(invalid)
            assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        }
        Files.delete(manifest)
        val error = assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        assertTrue(error.message.orEmpty().contains("complete application distribution"))
    }

    @Test
    fun `incompatible release is rejected even with matching checksum inventory`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"), version = "0.0.0")
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
    }

    @Test
    fun `installed worker initializes outside the application directory without an external installation`() = withFixture { root ->
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra API probe is opt-in")
        val bundle = BundledGhidra.locate()
        assertTrue(bundle.root.toString().contains("install/llm_bin_patch/libexec/ghidra"))
        val output = root.resolve("probe.log")
        val process = ProcessBuilder(bundle.probeCommand()).directory(root.toFile()).apply {
            environment().remove("GHIDRA_HOME")
            redirectErrorStream(true)
            redirectOutput(output.toFile())
        }.start()
        try {
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "bundled Ghidra probe timed out")
            assertEquals(0, process.exitValue(), output.readText())
            assertTrue(output.readText().contains("Bundled Ghidra direct API ready: ${BundledGhidra.VERSION}"))
            bundle.verify()
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor()
        }
    }

    @Test
    fun `installed worker requires the exact parent permit before Ghidra initialization`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra launch permit check is opt-in")
        inControlTemporaryDirectory { root ->
            // Authenticate once, then reuse the same installed bridge/classpath for every gate control.
            val probe = BundledGhidra.locate().probeCommand()
            assertEquals("probe", probe.last())
            assertEquals(BundledGhidra.WORKER_CLASS, probe[probe.lastIndex - 2])
            assertFalse("await-parent-launch" in probe, "legacy probe commands must remain ungated")
            val ready = "Bundled Ghidra direct API ready: ${BundledGhidra.VERSION}"
            val cases = listOf("valid" to "1\n", "eof" to "", "wrong-token" to "0\n", "wrong-terminator" to "1x", "truncated" to "1")
            for ((name, permit) in cases) {
                val valid = name == "valid"
                val work = root.resolve(name).createDirectories()
                val home = work.resolve("home").createDirectories()
                val temporary = work.resolve("tmp").createDirectories()
                val cache = work.resolve("cache").createDirectories()
                val output = work.resolve("probe.log")
                // Rejected permits must fail before even inspecting the release. If initialization
                // moves before the gate, this missing path causes a different failure immediately.
                val missingRelease = work.resolve("deliberately-missing-release")
                assertFalse(Files.exists(missingRelease))
                val release = if (valid) probe[probe.lastIndex - 1] else missingRelease.toString()
                val directoryNames = listOf("user.home", "java.io.tmpdir", "jna.tmpdir")
                val command = listOf(probe.first(), "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary") +
                    probe.drop(1).dropLast(2).filterNot { option -> directoryNames.any { option.startsWith("-D$it=") } } +
                    listOf(release, "await-parent-launch", probe.last())
                val process = ProcessBuilder(command).directory(work.toFile()).apply {
                    environment().remove("GHIDRA_HOME")
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["XDG_CACHE_HOME"] = cache.toString()
                    redirectErrorStream(true)
                    redirectOutput(output.toFile())
                }.start()
                try {
                    assertFalse(process.waitFor(250, TimeUnit.MILLISECONDS), "$name worker exited before receiving a permit")
                    assertFalse(output.readText().contains(ready), "$name worker reported readiness before parent authorization")
                    process.outputStream.use { it.write(permit.toByteArray(Charsets.US_ASCII)) }
                    assertTrue(process.waitFor(if (valid) 60 else 10, TimeUnit.SECONDS), "$name gated probe timed out")
                    val diagnostic = output.readText()
                    assertEquals(if (valid) 0 else 1, process.exitValue(), diagnostic)
                    if (valid) {
                        assertTrue(diagnostic.contains(ready), diagnostic)
                        assertFalse(diagnostic.contains("Parent did not authorize"), diagnostic)
                    } else {
                        assertTrue(diagnostic.lineSequence().any {
                            it == "java.lang.IllegalStateException: Parent did not authorize bundled analysis launch"
                        }, diagnostic)
                        assertFalse(diagnostic.contains(ready), diagnostic)
                    }
                } finally {
                    if (process.isAlive) process.destroyForcibly()
                    try {
                        assertTrue(process.waitFor(5, TimeUnit.SECONDS), "$name probe could not be reaped")
                    } finally {
                        process.outputStream.close()
                        process.inputStream.close()
                        process.errorStream.close()
                    }
                }
            }
        }
    }

    @Test
    fun `installed release retains exact original GCC provenance archive bytes and tree`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra provenance check is opt-in")
        val bundle = BundledGhidra.locate()
        val toolchain = GccCompilerEngineProfiles.load(Path.of("oracle/gcc/16.2.0/compiler-engines.json")).analysis
        val authentication = toolchain.authenticateGhidraInstallation(
            Path.of(System.getProperty("decompengine.ghidra.provenanceArchive")), bundle.release,
        )
        assertEquals(BundledGhidra.ARCHIVE_SHA256, authentication.archiveSha256)
        assertEquals(bundle.release, authentication.home)
        assertTrue(authentication.fileCount > 1000)
    }

    private fun fixture(root: Path, version: String = BundledGhidra.VERSION): BundledGhidra {
        val files = mapOf(
            "decomp-ghidra-bridge.jar" to "bridge fixture",
            "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Base/lib/Base.jar" to "library fixture",
            "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/application.properties" to "application.version=$version\napplication.release.name=PUBLIC\n",
        )
        files.forEach { (relative, content) ->
            root.resolve(relative).also { it.parent.createDirectories(); it.writeText(content) }
        }
        root.resolve("bundle.sha256").writeText(files.toSortedMap().entries.joinToString("") { (relative, content) ->
            "${sha256(content.toByteArray())}  $relative\n"
        })
        return BundledGhidra.at(root)
    }

    private fun withFixture(block: (Path) -> Unit) {
        val parent = Path.of("build/bundled-ghidra-directory-tests").toAbsolutePath().normalize().createDirectories()
        val root = createTempDirectory(parent, "bundled-ghidra-test-")
        try {
            val home = root.resolve("home").createDirectories()
            val temporary = root.resolve("tmp").createDirectories()
            withParentDirectoryProperties(mapOf(
                "user.home" to home.toString(), "java.io.tmpdir" to temporary.toString(), "jna.tmpdir" to temporary.toString(),
            )) { block(root) }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun withParentDirectoryProperties(values: Map<String, String?>, block: () -> Unit) {
        val previous = values.keys.associateWith(System::getProperty)
        try {
            values.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
            block()
        } finally {
            previous.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
        }
    }
}

/** Runs with test classes and installed JARs only; development reference overrides are absent. */
object BundledGhidraInstalledNativeCollectorProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        check(arguments.size == 4)
        val expectedApplication = Path.of(arguments[0]).toRealPath()
        val expectedBundle = Path.of(arguments[1]).toRealPath()
        val trackedSource = Path.of(arguments[2]).toRealPath()
        val compiledClasses = Path.of(arguments[3]).toRealPath()
        val application = Path.of(GccBundledGhidraDeploymentReference::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
        check(application == expectedApplication && Files.isRegularFile(application, LinkOption.NOFOLLOW_LINKS)) {
            "native collector probe did not load the exact installed application JAR"
        }
        check(System.getProperty("decompengine.oracle.gcc.bundledGhidraReference") == null &&
            System.getProperty("decompengine.oracle.gcc.bundledGhidraRoot") == null) {
            "installed native reference check cannot use development fallbacks"
        }
        GccBundledGhidraDeploymentReference.open().use { deployment ->
            check(deployment.bundleRoot == expectedBundle)
            val reference = deployment.reference
            val collector = checkNotNull(reference.nativeCallCollector) { "installed reference has no native collector identity" }
            fun collectorClass(name: String): Boolean = name.substringAfterLast('/').let {
                it.startsWith("ExportNativeCallsV1") && it.endsWith(".class")
            }
            val declaredClasses = reference.entries.values.filter { it.path.startsWith("scripts/") && collectorClass(it.path) }
                .associateBy { it.path }
            check("scripts/ExportNativeCallsV1.class" in declaredClasses && declaredClasses.size > 1) {
                "installed reference omits the collector's primary or nested compiled classes"
            }
            val actualClasses = Files.list(expectedBundle.resolve("scripts")).use { paths ->
                paths.filter { collectorClass(it.fileName.toString()) }.limit(513).toList()
            }
            check(actualClasses.size in 2..512)
            check(actualClasses.map { "scripts/${it.fileName}" }.toSet() == declaredClasses.keys) {
                "installed collector classes differ from the complete declared closure"
            }
            val compiled = Files.list(compiledClasses).use { paths -> paths.filter { collectorClass(it.fileName.toString()) }.limit(513).toList() }
            check(compiled.size in 2..512 && compiled.map { "scripts/${it.fileName}" }.toSet() == declaredClasses.keys) {
                "installed native collector closure omits or adds classes from the actual Java compilation"
            }
            for (path in actualClasses) {
                check(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path)
                val entry = declaredClasses.getValue("scripts/${path.fileName}")
                val expectedBytes = checkNotNull(entry.bytes)
                check(entry.kind == "file" && expectedBytes == Files.size(path) && expectedBytes in 1..128L * 1024 * 1024)
                val bytes = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(expectedBytes.toInt() + 1) }
                check(bytes.size.toLong() == entry.bytes && sha256(bytes) == entry.sha256) {
                    "installed native collector class does not match its independent identity: ${entry.path}"
                }
                val compiledPath = compiledClasses.resolve(path.fileName)
                check(Files.isRegularFile(compiledPath, LinkOption.NOFOLLOW_LINKS) && compiledPath.toRealPath() == compiledPath &&
                    Files.size(compiledPath) == expectedBytes)
                val compiledBytes = Files.newInputStream(compiledPath, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(expectedBytes.toInt() + 1) }
                check(compiledBytes.contentEquals(bytes)) { "installed collector bytes differ from their actual Java compilation" }
            }
            val primary = declaredClasses.getValue("scripts/ExportNativeCallsV1.class")
            check(primary.bytes == collector.classBytes && primary.sha256 == collector.classSha256)
            JarFile(expectedBundle.resolve("decomp-ghidra-bridge.jar").toFile(), false).use { bridge ->
                val entries = bridge.entries().asSequence().take(200_001).toList()
                check(entries.size <= 200_000 && entries.none { collectorClass(it.name) }) {
                    "bridge JAR contains duplicate native collector implementations"
                }
            }
            check(Files.isRegularFile(trackedSource, LinkOption.NOFOLLOW_LINKS) && Files.size(trackedSource) in 1..4L * 1024 * 1024)
            val sourceBytes = Files.newInputStream(trackedSource, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(4 * 1024 * 1024 + 1) }
            check(sourceBytes.size.toLong() == collector.sourceBytes && sha256(sourceBytes) == collector.sourceSha256)
            JarFile(application.toFile(), false).use { jar ->
                val entries = jar.entries().asSequence().take(200_001).toList()
                check(entries.size <= 200_000 && entries.none { collectorClass(it.name) })
                val resource = entries.single { it.name == "ghidra_scripts/ExportNativeCallsV1.java" }
                check(!resource.isDirectory && resource.size == collector.sourceBytes)
                val packaged = jar.getInputStream(resource).use { it.readNBytes(4 * 1024 * 1024 + 1) }
                check(packaged.contentEquals(sourceBytes) && sha256(packaged) == collector.sourceSha256) {
                    "installed native collector resource was not generated from the single tracked Java source"
                }
            }
            deployment.verify("after installed native collector source and complete class closure checks")
            println("installed-native-collector-reference-verified:${reference.closureSha256}:classes=${actualClasses.size}")
        }
    }
}
