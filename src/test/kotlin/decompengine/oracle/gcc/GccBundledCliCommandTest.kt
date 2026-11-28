package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleJson
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledCliCommandTest {
    @Test
    fun `options select explicit scratch policy and same-owner checkpoint resume`() = fixture { root ->
        val args = arguments(root)
        val fresh = GccBundledCliOptions.parse(args)
        assertEquals("cc1", fresh.engineId)
        assertEquals(null, fresh.resumeAfterCheckpoint)
        assertEquals(8L * 1024 * 1024 * 1024, fresh.diskPolicy.requiredAvailableBytes)
        val resumed = GccBundledCliOptions.parse(args + listOf("--resume-after-checkpoint", "1024",
            "--scratch-min-bytes", "1048576", "--scratch-max-bytes", "2097152",
            "--scratch-min-inodes", "128", "--scratch-max-inodes", "256"))
        assertEquals(1024L, resumed.resumeAfterCheckpoint)
        assertEquals(2097152L, resumed.diskPolicy.maximumFilesystemBytes)
        assertEquals(256L, resumed.diskPolicy.maximumFilesystemInodes)
        val fullExport = GccBundledCliOptions.parse(args, fullRecoveryExport = true)
        assertTrue(fullExport.fullRecoveryExport)
        assertEquals(null, fullExport.resumeAfterCheckpoint)
        assertFails { GccBundledCliOptions.parse(args.mapIndexed { index, value -> if (index == 0) "lto1" else value }, fullRecoveryExport = true) }
        assertFails { GccBundledCliOptions.parse(args + listOf("--resume-after-checkpoint", "1024"), fullRecoveryExport = true) }
    }

    @Test
    fun `runtime diagnostics require a distinct fresh cc1 invocation`() = fixture { root ->
        val args = arguments(root)
        val diagnostic = GccBundledCliOptions.parse(args, fullRecoveryExport = true, runtimeDiagnostics = true)
        assertTrue(diagnostic.runtimeDiagnostics)
        assertEquals("gcc-engine-runtime-diagnostic", diagnostic.commandName)
        assertFails { GccBundledCliOptions.parse(args, runtimeDiagnostics = true) }
        for (engine in listOf("driver", "lto1")) {
            assertFails { GccBundledCliOptions.parse(listOf(engine) + args.drop(1), fullRecoveryExport = true, runtimeDiagnostics = true) }
        }
        assertFails { GccBundledCliOptions.parse(args + listOf("--resume-after-checkpoint", "512"), fullRecoveryExport = true, runtimeDiagnostics = true) }
        val children = listOf(diagnostic.output, privateDirectory(diagnostic.output.resolve("inputs")),
            privateDirectory(diagnostic.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(diagnostic, args, identities)
        val document = OracleJson.parseCanonical(invocation.canonicalBytes).jsonObject
        assertEquals("gcc-engine-runtime-diagnostic", document.getValue("argv").jsonArray.first().jsonPrimitive.content)
        assertFalse(invocation.canonicalBytes.contentEquals(
            GccBundledCliInvocation(GccBundledCliOptions.parse(args, fullRecoveryExport = true), args, identities).canonicalBytes))
    }

    @Test
    fun `driver selection is bound to full fresh invocation and rejects compiler substitution`() = fixture { root ->
        val args = listOf("driver") + arguments(root).drop(1)
        val options = GccBundledCliOptions.parse(args, fullRecoveryExport = true)
        assertEquals("driver", options.engineId)
        assertEquals(null, options.resumeAfterCheckpoint)
        assertFails { GccBundledCliOptions.parse(args) }
        assertFails { GccBundledCliOptions.parse(args + listOf("--resume-after-checkpoint", "512"), fullRecoveryExport = true) }
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, args, identities)
        val document = OracleJson.parseCanonical(invocation.canonicalBytes).jsonObject
        assertEquals("driver", document.getValue("engineId").jsonPrimitive.content)
        assertEquals("gcc-engine-full-export", document.getValue("argv").jsonArray.first().jsonPrimitive.content)
        assertFails { GccBundledCliInvocation(options, listOf("cc1") + args.drop(1), identities) }
    }

    @Test
    fun `reject duplicate missing conflicting unknown and detached resume options`() = fixture { root ->
        val args = arguments(root)
        val invalid = listOf(args + listOf("--profile", root.resolve("profile").toString()),
            args + listOf("--unknown", "value"), args + "--resume-after-checkpoint",
            args + listOf("--resume", "receipt.json"), args + listOf("--resume-after-checkpoint", "513"),
            args + listOf("--resume-after-checkpoint", "0"), args + listOf("--scratch-max-bytes", "1e9"),
            args + listOf("--scratch-min-inodes", "-1"), args + listOf("--scratch-min-bytes", "99999999999999999999999"),
            args + listOf("--scratch-max-bytes", "1"), args + "extra", listOf("driver") + args.drop(1),
            args.dropLast(2), args.map { if (it == root.resolve("scratch").toString()) root.resolve("output").toString() else it })
        invalid.forEach { candidate -> assertFails { GccBundledCliOptions.parse(candidate) } }
    }

    @Test
    fun `bound invocation rejects directory replacement and inconsistent argv`() = fixture { root ->
        val args = arguments(root)
        val options = GccBundledCliOptions.parse(args)
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, args, identities)
        invocation.requireCurrent()
        val document = OracleJson.parseCanonical(invocation.canonicalBytes).jsonObject
        assertEquals("fresh", document.getValue("resumeMode").jsonPrimitive.content)
        assertFails { GccBundledCliInvocation(options, args + listOf("--resume-after-checkpoint", "512"), identities) }
        Files.move(options.output.resolve("inputs"), options.output.resolve("old-inputs"))
        privateDirectory(options.output.resolve("inputs"))
        assertFails { invocation.requireCurrent() }
    }

    @Test
    fun `full recovery mode is fixed by the distinct invocation command`() = fixture { root ->
        val args = arguments(root)
        val options = GccBundledCliOptions.parse(args, fullRecoveryExport = true)
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, args, identities)
        val document = OracleJson.parseCanonical(invocation.canonicalBytes).jsonObject
        assertEquals("gcc-engine-full-export", document.getValue("argv").jsonArray.first().jsonPrimitive.content)
        val planning = GccBundledCliInvocation(GccBundledCliOptions.parse(args), args, identities)
        val planningDocument = OracleJson.parseCanonical(planning.canonicalBytes).jsonObject
        assertEquals("gcc-engine-plan", planningDocument.getValue("argv").jsonArray.first().jsonPrimitive.content)
    }

    @Test
    fun `native call command is fresh cc1 or driver and cannot select scripts or legacy export mode`() {
        for (engine in listOf("cc1", "driver")) fixture { root ->
            val args = listOf(engine) + arguments(root).drop(1)
            val options = GccBundledCliOptions.parse(args, nativeCallObservations = true)
            assertTrue(options.nativeCallObservations)
            assertFalse(options.fullRecoveryExport)
            assertFalse(options.runtimeDiagnostics)
            assertEquals("gcc-engine-native-calls", options.commandName)
            val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
            val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
            val document = OracleJson.parseCanonical(GccBundledCliInvocation(options, args, identities).canonicalBytes).jsonObject
            assertEquals("gcc-engine-native-calls", document.getValue("argv").jsonArray.first().jsonPrimitive.content)
            assertEquals(engine, document.getValue("engineId").jsonPrimitive.content)
            assertEquals("<cc1|driver>", GccBundledCliOptions.engineUsage(false, nativeCallObservations = true))
            assertEquals("cc1|driver", GccBundledCliOptions.engineArgumentUsage(false, nativeCallObservations = true))
            for (bad in listOf(args + listOf("--resume-after-checkpoint", "512"),
                args + listOf("--collector", "Other.class"), args + listOf("--script", "Other.java"),
                listOf("lto1") + args.drop(1))) {
                assertFails { GccBundledCliOptions.parse(bad, nativeCallObservations = true) }
            }
            assertFails { GccBundledCliOptions.parse(args, fullRecoveryExport = true, nativeCallObservations = true) }
            assertFails { GccBundledCliOptions.parse(args, fullRecoveryExport = true, runtimeDiagnostics = true, nativeCallObservations = true) }
            assertFails { GccBundledCliOptions.parse(args, runtimeDiagnostics = true, nativeCallObservations = true) }
            assertFails { GccBundledCliInvocation(options.copy(nativeCallObservations = false), args, identities).also {
                GccBundledCliIntentBuilder.build("a".repeat(64), engine, GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                    options.binary, options.profile, options.archive, options.output.resolve("inputs"), options.output.resolve("journal"),
                    options.scratch, options.diskPolicy, it, nativeCallObservations = true)
            } }
            val otherEngine = if (engine == "cc1") "driver" else "cc1"
            assertFails { GccBundledCliInvocation(options, listOf(otherEngine) + args.drop(1), identities) }
            assertFails {
                val invocation = GccBundledCliInvocation(options, args, identities)
                GccBundledCliIntentBuilder.build("a".repeat(64), otherEngine, GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                    options.binary, options.profile, options.archive, options.output.resolve("inputs"), options.output.resolve("journal"),
                    options.scratch, options.diskPolicy, invocation, nativeCallObservations = true)
            }
            for (path in children.drop(1)) Files.list(path).use { assertEquals(0L, it.count()) }
        }
    }

    @Test
    fun `native call CLI rejects an untrusted selected binary before leasing or publishing evidence`() {
        for (engine in listOf("cc1", "driver")) fixture { root ->
            val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
            val args = (listOf(engine) + arguments(root).drop(1))
                .map { if (it == root.resolve("profile").toString()) profile.toString() else it }
            val options = GccBundledCliOptions.parse(args, nativeCallObservations = true)
            val failure = assertFails { GccBundledCliCommand.run(options, args) }
            assertTrue(failure.message.orEmpty().contains("binary differs from selected profile engine"), failure.toString())
            val invocation = OracleJson.parseCanonical(Files.readAllBytes(options.output.resolve("invocation.json"))).jsonObject
            assertEquals("gcc-engine-native-calls", invocation.getValue("argv").jsonArray.first().jsonPrimitive.content)
            assertEquals(engine, invocation.getValue("engineId").jsonPrimitive.content)
            assertFalse(Files.exists(options.output.resolve("result.json")))
            for (path in listOf(options.output.resolve("inputs"), options.output.resolve("journal"), options.scratch)) {
                Files.list(path).use { assertEquals(0L, it.count()) }
            }
        }
    }

    @Test
    fun `checkpoint selection must match the exact invocation threshold`() = fixture { root ->
        val args = arguments(root)
        val options = GccBundledCliOptions.parse(args)
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val fresh = GccBundledCliInvocation(options, args, identities)
        assertFails { fresh.requireCheckpointSelection(512) }
        val resumedArgs = args + listOf("--resume-after-checkpoint", "1024")
        val resumed = GccBundledCliInvocation(GccBundledCliOptions.parse(resumedArgs), resumedArgs, identities)
        resumed.requireCheckpointSelection(1024)
        for (threshold in listOf(0L, 512L, 1023L, 1536L, Long.MAX_VALUE)) {
            assertFails { resumed.requireCheckpointSelection(threshold) }
        }
        resumed.requireCurrent()
        for (path in children.drop(1)) Files.list(path).use { assertEquals(0L, it.count()) }
    }

    @Test
    fun `later-invocation recovery option is bound to an interrupted plan selection`() = fixture { root ->
        val interrupted = arguments(root) + listOf("--resume-after-checkpoint", "512")
        val selector = listOf("--recover-operation", RECOVERED_OPERATION)
        val recovery = GccBundledCliOptions.parse(interrupted + selector)
        assertEquals(RECOVERED_OPERATION, recovery.recoverOperationId)
        assertEquals("gcc-engine-plan", recovery.commandName)
        assertEquals(GccBundledCliOptions.parse(interrupted), recovery.copy(recoverOperationId = null))
        for (bad in listOf(arguments(root) + selector, interrupted + listOf("--recover-operation", "A".repeat(64)),
            interrupted + listOf("--recover-operation", "a".repeat(63)), interrupted + selector + selector,
            interrupted + "--recover-operation")) {
            assertFails { GccBundledCliOptions.parse(bad) }
        }
        assertFails { GccBundledCliOptions.parse(arguments(root) + selector, fullRecoveryExport = true) }
        assertFails { GccBundledCliOptions.parse(arguments(root) + selector, nativeCallObservations = true) }
        assertFails { GccBundledCliOptions.parse(arguments(root) + selector, fullRecoveryExport = true, runtimeDiagnostics = true) }
        val children = listOf(recovery.output, privateDirectory(recovery.output.resolve("inputs")),
            privateDirectory(recovery.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        // A later-invocation selection is never itself retained as an invocation or admitted as fresh work.
        assertFails { GccBundledCliInvocation(recovery, interrupted + selector, identities) }
        assertFails { GccBundledCliCommand.admit(recovery, interrupted + selector) }
        for (path in children.drop(1) + listOf(recovery.scratch)) Files.list(path).use { assertEquals(0L, it.count()) }
        assertEquals(listOf("inputs", "journal"), Files.list(recovery.output).use { it.map { p -> p.fileName.toString() }.sorted().toList() })
    }

    @Test
    fun `later-invocation recovery refuses changed argv and finished output before any journal or lease`() = fixture { root ->
        val interrupted = arguments(root) + listOf("--resume-after-checkpoint", "512")
        val options = GccBundledCliOptions.parse(interrupted)
        val output = options.output
        val children = listOf(output, privateDirectory(output.resolve("inputs")), privateDirectory(output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        // The earlier invocation's retained selection, exactly as admission publishes it.
        LinuxFilesystemSyscalls.openRoot(output).use { selected ->
            DescriptorBoundAtomicStateFile.publishNoReplace(selected, "invocation.json",
                GccBundledCliInvocation(options, interrupted, identities).canonicalBytes, 256 * 1024)
        }
        val retained = Files.readAllBytes(output.resolve("invocation.json"))
        fun refused(arguments: List<String>): String = assertFails {
            GccBundledCliCommand.run(GccBundledCliOptions.parse(arguments), arguments)
        }.message.orEmpty()
        val selector = listOf("--recover-operation", RECOVERED_OPERATION)
        assertTrue(refused(interrupted + listOf("--scratch-min-bytes", "1048576") + selector)
            .contains("differs from the retained invocation"))
        val reordered = interrupted.take(2) + interrupted.drop(4).take(2) + interrupted.drop(2).take(2) + interrupted.drop(6)
        assertEquals(options, GccBundledCliOptions.parse(reordered))
        assertTrue(refused(reordered + selector).contains("differs from the retained invocation"))
        // The exact argv authenticates, then the earlier owner's staged controls are required before any journal lock.
        assertTrue(refused(selector + interrupted).contains("retain exactly its two staged controls"))
        for (path in children.drop(1) + listOf(options.scratch)) Files.list(path).use { assertEquals(0L, it.count()) }
        Files.writeString(output.resolve("result.json"), "{}")
        assertTrue(refused(interrupted + selector).contains("unfinished interrupted invocation"))
        assertContentEquals(retained, Files.readAllBytes(output.resolve("invocation.json")))
        for (path in children.drop(1) + listOf(options.scratch)) Files.list(path).use { assertEquals(0L, it.count()) }
    }

    @Test
    fun `later-invocation recovery from another working directory is refused against the retained invocation`() = fixture { root ->
        val interrupted = arguments(root) + listOf("--resume-after-checkpoint", "512")
        val options = GccBundledCliOptions.parse(interrupted)
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")),
            privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val current = GccBundledCliWorkingDirectory.current()
        assertEquals(current, GccBundledCliInvocation(options, interrupted, identities).workingDirectory)
        val elsewhere = GccBundledCliWorkingDirectory(root, LinuxFilesystemSyscalls.openRoot(root).use { it.identity })
        assertFalse(current == elsewhere)
        val retained = GccBundledCliInvocation(options, interrupted, identities, elsewhere)
        val document = OracleJson.parseCanonical(retained.canonicalBytes).jsonObject
        assertEquals("gcc-bundled-cli-invocation-v2", document.getValue("provider").jsonPrimitive.content)
        assertEquals(root.toString(), document.getValue("workingDirectory").jsonObject.getValue("path").jsonPrimitive.content)
        assertEquals(LinuxFilesystemSyscalls.openRoot(root).use { it.identity.key.inode },
            document.getValue("workingDirectory").jsonObject.getValue("inode").jsonPrimitive.content.toLong())
        LinuxFilesystemSyscalls.openRoot(options.output).use { selected ->
            DescriptorBoundAtomicStateFile.publishNoReplace(selected, "invocation.json", retained.canonicalBytes, 256 * 1024)
        }
        val recovery = interrupted + listOf("--recover-operation", RECOVERED_OPERATION)
        val failure = assertFails { GccBundledCliCommand.run(GccBundledCliOptions.parse(recovery), recovery) }
        assertTrue(failure.message.orEmpty().contains("differs from the retained invocation"), failure.toString())
        for (path in children.drop(1) + listOf(options.scratch)) Files.list(path).use { assertEquals(0L, it.count()) }
    }

    @Test
    fun `an unreadable but searchable working directory is pinned and recorded by the actual CLI`() = fixture { root ->
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
        val args = arguments(root).map { if (it == root.resolve("profile").toString()) profile.toString() else it } +
            listOf("--resume-after-checkpoint", "512")
        val workingDirectory = privateDirectory(root.resolve("searchable-only"))
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            parseBootClassPathManifest(reference.invocationManifestBytes(), root, emptySet()).joinToString(File.pathSeparator) { it.path.toString() }
        }
        val log = root.resolve("searchable-only.log")
        // Search (x) without read (r): O_PATH and realpath(3) succeed where a read-only directory open would not.
        Files.setPosixFilePermissions(workingDirectory, PosixFilePermissions.fromString("-wx------"))
        try {
            // The installed launcher's -XX:-UsePerfData keeps HotSpot from relocating this unreadable directory.
            val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx256m",
                "-XX:-UsePerfData", "-cp", classpath, "decompengine.MainKt", "gcc-engine-plan") + args)
                .directory(workingDirectory.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS))
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            }
            val output = Files.readString(log).take(8192)
            assertTrue(process.exitValue() != 0, output)
            // Admission got past the working directory and the bound output; only the fixture binary is refused.
            assertTrue(output.contains("binary differs from selected profile engine"), output)
        } finally {
            Files.setPosixFilePermissions(workingDirectory, PosixFilePermissions.fromString("rwx------"))
        }
        val invocation = OracleJson.parseCanonical(Files.readAllBytes(root.resolve("output/invocation.json"))).jsonObject
        val recorded = invocation.getValue("workingDirectory").jsonObject
        assertEquals(workingDirectory.toString(), recorded.getValue("path").jsonPrimitive.content)
        val identity = LinuxFilesystemSyscalls.openRoot(workingDirectory).use { it.identity }
        assertEquals(identity.key.inode, recorded.getValue("inode").jsonPrimitive.content.toLong())
        assertEquals(identity.key.device, recorded.getValue("device").jsonPrimitive.content.toLong())
        assertEquals(identity.mountId, recorded.getValue("mountId").jsonPrimitive.content.toLong())
        // A working directory HotSpot relocated into its perf-data directory is refused rather than bound.
        val relocated = assertFails {
            GccBundledCliWorkingDirectory.requireNotRelocatedByJvm(Path.of("/tmp", "hsperfdata_" + System.getProperty("user.name")))
        }
        assertTrue(relocated.message.orEmpty().contains("-XX:-UsePerfData"), relocated.toString())
        GccBundledCliWorkingDirectory.requireNotRelocatedByJvm(workingDirectory)
    }

    @Test
    fun `a failed working-directory capture leaves the output empty and usable for a retry`() = fixture { root ->
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
        val args = arguments(root).map { if (it == root.resolve("profile").toString()) profile.toString() else it }
        val options = GccBundledCliOptions.parse(args)
        val failure = assertFails { GccBundledCliCommand.admit(options, args) { error("working directory capture failed") } }
        assertTrue(failure.message.orEmpty().contains("working directory capture failed"), failure.toString())
        Files.list(options.output).use { assertEquals(0L, it.count()) }
        // The retry is admitted against the same still-empty output and fails only on the fixture binary.
        val retry = assertFails { GccBundledCliCommand.run(options, args) }
        assertTrue(retry.message.orEmpty().contains("binary differs from selected profile engine"), retry.toString())
        assertEquals(listOf("inputs", "invocation.json", "journal"),
            Files.list(options.output).use { it.map { path -> path.fileName.toString() }.sorted().toList() })
    }

    @Test
    fun `command records selection but refuses a mismatched binary before staging or leasing`() = fixture { root ->
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
        val args = arguments(root).map { if (it == root.resolve("profile").toString()) profile.toString() else it }
        val options = GccBundledCliOptions.parse(args)
        val failure = assertFails { GccBundledCliCommand.run(options, args) }
        assertTrue(failure.message.orEmpty().contains("binary differs from selected profile engine"), failure.toString())
        assertTrue(Files.isRegularFile(options.output.resolve("invocation.json")))
        for (path in listOf(options.output.resolve("inputs"), options.output.resolve("journal"), options.scratch)) {
            Files.list(path).use { assertEquals(0L, it.count()) }
        }
        assertFalse(Files.exists(options.output.resolve("result.json")))
        assertFails { GccBundledCliCommand.run(options, args) }
    }

    @Test
    fun `command rejects an unreachable profile checkpoint before staging or leasing`() = fixture { root ->
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
        val args = arguments(root).map { if (it == root.resolve("profile").toString()) profile.toString() else it } +
            listOf("--resume-after-checkpoint", "16777216")
        val options = GccBundledCliOptions.parse(args)
        val failure = assertFails { GccBundledCliCommand.run(options, args) }
        assertTrue(failure.message.orEmpty().contains("cannot be reached within the profile planner entity bound"), failure.toString())
        for (path in listOf(options.output.resolve("inputs"), options.output.resolve("journal"), options.scratch)) {
            Files.list(path).use { assertEquals(0L, it.count()) }
        }
        assertFalse(Files.exists(options.output.resolve("result.json")))
    }

    @Test
    fun `full export CLI records its mode before rejecting an untrusted binary`() {
        for (engine in listOf("cc1", "driver")) fixture { root ->
            val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
            val args = (listOf(engine) + arguments(root).drop(1))
                .map { if (it == root.resolve("profile").toString()) profile.toString() else it }
            val options = GccBundledCliOptions.parse(args, fullRecoveryExport = true)
            val failure = assertFails { GccBundledCliCommand.run(options, args) }
            assertTrue(failure.message.orEmpty().contains("binary differs from selected profile engine"), failure.toString())
            val invocation = OracleJson.parseCanonical(Files.readAllBytes(options.output.resolve("invocation.json"))).jsonObject
            assertEquals("gcc-engine-full-export", invocation.getValue("argv").jsonArray.first().jsonPrimitive.content)
            assertEquals(engine, invocation.getValue("engineId").jsonPrimitive.content)
            assertFalse(Files.exists(options.output.resolve("structural-full-export-binding.json")))
            assertFalse(Files.exists(options.output.resolve("result.json")))
            for (path in listOf(options.output.resolve("inputs"), options.output.resolve("journal"), options.scratch)) {
                Files.list(path).use { assertEquals(0L, it.count()) }
            }
        }
    }

    @Test
    fun `actual CLI rejects duplicate options and nonempty output without overwriting files`() = fixture { root ->
        val args = arguments(root)
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            parseBootClassPathManifest(reference.invocationManifestBytes(), root, emptySet()).joinToString(File.pathSeparator) { it.path.toString() }
        }
        fun invoke(arguments: List<String>): Pair<Int, String> {
            val log = Files.createTempFile(root, "cli-", ".log")
            val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx256m",
                "-cp", classpath, "decompengine.MainKt", "gcc-engine-plan") + arguments)
                .redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS))
                return process.exitValue() to Files.readString(log).take(8192)
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            }
        }
        val duplicate = invoke(args + listOf("--profile", root.resolve("profile").toString()))
        assertEquals(2, duplicate.first)
        assertTrue(duplicate.second.contains("duplicate option"), duplicate.second)
        val prior = Files.writeString(root.resolve("output/prior"), "preserve me")
        val nonempty = invoke(args)
        assertTrue(nonempty.first != 0)
        assertTrue(nonempty.second.contains("existing empty private directory"), nonempty.second)
        assertEquals("preserve me", Files.readString(prior))
        Files.list(root.resolve("output")).use { assertEquals(1L, it.count()) }
    }

    private companion object {
        val RECOVERED_OPERATION = "a".repeat(64)
    }

    private fun arguments(root: Path) = listOf("cc1", root.resolve("binary").toString(), "--profile", root.resolve("profile").toString(),
        "--ghidra-archive", root.resolve("archive").toString(), "--output", root.resolve("output").toString(), "--scratch", root.resolve("scratch").toString())
    private fun privateDirectory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun fixture(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "gcc-contained-cli-").toRealPath()
        try {
            listOf("binary", "profile", "archive").forEach { Files.writeString(root.resolve(it), "fixture") }
            listOf("output", "scratch").forEach { privateDirectory(root.resolve(it)) }
            action(root)
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
