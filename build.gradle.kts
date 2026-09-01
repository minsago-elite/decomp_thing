import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.jar.Attributes
import java.util.jar.JarFile

plugins {
    kotlin("jvm") version "2.4.0"
    application
}

group = "dev.decompengine"
version = "0.1.0"

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("decompengine.MainKt")
    applicationName = "llm_bin_patch"
}

fun registerOracleJavaExecTask(
    taskName: String,
    taskDescription: String,
    entryPoint: String,
) = tasks.register<JavaExec>(taskName) {
    group = "oracle"
    description = taskDescription
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set(entryPoint)
}

registerOracleJavaExecTask(
    taskName = "verifyFullTreeScope",
    taskDescription = "Verifies the authenticated LLVM full-tree scope with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.fulltree.FullTreeScopeVerifierCli",
)

registerOracleJavaExecTask(
    taskName = "generateFullTreeInventory",
    taskDescription = "Generates the authenticated LLVM full-tree inventory with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.fulltree.FullTreeInventoryGeneratorCli",
)

registerOracleJavaExecTask(
    taskName = "generateFullTreeSourceInventory",
    taskDescription = "Generates the authenticated LLVM source inventory with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.fulltree.FullTreeSourceInventoryGeneratorCli",
)

registerOracleJavaExecTask(
    taskName = "generateFullTreePlanningInventory",
    taskDescription = "Generates the authenticated LLVM source-module planning inventory with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.fulltree.FullTreePlanningInventoryGeneratorCli",
)

registerOracleJavaExecTask(
    taskName = "fetchLlvmReleaseArtifacts",
    taskDescription = "Fetches and authenticates the hash-locked LLVM oracle release artifacts in Kotlin/JVM",
    entryPoint = "decompengine.oracle.provenance.LlvmReleaseArtifactFetcherCli",
)

registerOracleJavaExecTask(
    taskName = "fetchLlvmSourceArchive",
    taskDescription = "Fetches and authenticates the locked LLVM source archive in Kotlin/JVM",
    entryPoint = "decompengine.oracle.provenance.LlvmSourceArchiveFetcherCli",
)

registerOracleJavaExecTask(
    taskName = "verifyLlvmToolchainReproduction",
    taskDescription = "Verifies the stable LLVM toolchain recipe and rebuilt image identity in Kotlin/JVM",
    entryPoint = "decompengine.oracle.provenance.LlvmToolchainReproductionVerifierCli",
)

registerOracleJavaExecTask(
    taskName = "verifyLlvmOracleBuildRecord",
    taskDescription = "Verifies LLVM build-record origin and live tools after separate image reproduction authentication",
    entryPoint = "decompengine.oracle.provenance.LlvmBuildEnvironmentVerifierCli",
)

registerOracleJavaExecTask(
    taskName = "verifyLlvmOracleArtifacts",
    taskDescription = "Verifies the checked LLVM ELF artifact manifest with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.provenance.LlvmArtifactManifestVerifierCli",
)

registerOracleJavaExecTask(
    taskName = "generateLlvmFunctionRecoveryOracle",
    taskDescription = "Generates the authenticated LLVM function-recovery oracle with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.provenance.LlvmFunctionOracleGeneratorCli",
)

registerOracleJavaExecTask(
    taskName = "verifyLlvmBehaviorReferenceEvidence",
    taskDescription = "Authenticates checked LLVM behavior and diagnostic reference evidence in Kotlin/JVM",
    entryPoint = "decompengine.oracle.behavior.LlvmBehaviorReferenceEvidenceCli",
)

val acpGateHelperSource = layout.projectDirectory.file("src/main/c/decomp_acp_gate_helper.c")
val acpGateHelperBinary = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper")
val acpGateHelperChecksum = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper.sha256")
val acpGateHelperCompiler = providers.gradleProperty("acpGateHelperCompiler").orElse("/usr/bin/cc")
val llvmBehaviorHelperSource = layout.projectDirectory.file("src/main/c/decomp_llvm_behavior_helper.c")
val llvmBehaviorHelperBinary = layout.buildDirectory.file("native/behavior/decomp-llvm-behavior-helper")
val llvmBehaviorHelperChecksum = layout.buildDirectory.file("native/behavior/decomp-llvm-behavior-helper.sha256")
val llvmBehaviorHelperCompiler = providers.gradleProperty("llvmBehaviorHelperCompiler").orElse("/usr/bin/cc")
val kotlinBootRuntimeDirectory = layout.buildDirectory.dir("oracle/gcc/kotlin-boot-runtime")
val kotlinBootClasspathReference =
    layout.buildDirectory.file("generated/oracle/gcc/kotlin-boot-classpath-reference-v1.json")

fun sha256(path: java.nio.file.Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(1024 * 1024)
    Files.newInputStream(path).use { input ->
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read > 0) digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}

fun canonicalJsonString(value: String): String = buildString {
    append('"')
    value.forEach { character ->
        when (character) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u")
                append(character.code.toString(16).padStart(4, '0'))
            } else {
                append(character)
            }
        }
    }
    append('"')
}

val stageKotlinBootRuntime = tasks.register<Sync>("stageKotlinBootRuntime") {
    group = "distribution"
    description = "Stages the exact deployment-owned JVM closure for the Kotlin BOOT keeper"
    dependsOn(tasks.named("jar"))
    duplicatesStrategy = DuplicatesStrategy.FAIL
    into(kotlinBootRuntimeDirectory)
    from(tasks.named("jar"))
    from(configurations.runtimeClasspath)
}

val generateKotlinBootClasspathReference = tasks.register("generateKotlinBootClasspathReference") {
    group = "distribution"
    description = "Generates the external digest reference for the Kotlin BOOT keeper JVM closure"
    dependsOn(stageKotlinBootRuntime)
    inputs.dir(kotlinBootRuntimeDirectory)
    outputs.file(kotlinBootClasspathReference)

    doLast {
        val runtimeRoot = kotlinBootRuntimeDirectory.get().asFile.toPath()
        val mainName = tasks.named<Jar>("jar").get().archiveFile.get().asFile.name
        val dependencyNames = configurations.runtimeClasspath.get().files.map { it.name }.sorted()
        val names = listOf(mainName) + dependencyNames
        require(names.size in 1..512 && names.toSet().size == names.size) {
            "Kotlin BOOT runtime closure has duplicate or excessive logical JAR names"
        }
        require(names.all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,255}\\.jar")) }) {
            "Kotlin BOOT runtime closure contains an unsafe logical JAR name"
        }
        val stagedNames = Files.list(runtimeRoot).use { stream ->
            stream.map { it.fileName.toString() }.sorted().toList()
        }
        require(stagedNames == names.sorted()) {
            "staged Kotlin BOOT runtime differs from the exact reference input set"
        }
        var totalBytes = 0L
        var keeperClasses = 0
        val entries = names.map { name ->
            val path = runtimeRoot.resolve(name)
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                "Kotlin BOOT runtime entry is not a regular JAR: $name"
            }
            val bytes = Files.size(path)
            require(bytes in 1L..(1024L * 1024L * 1024L)) {
                "Kotlin BOOT runtime JAR exceeds its per-entry bound: $name"
            }
            totalBytes = Math.addExact(totalBytes, bytes)
            require(totalBytes <= 2L * 1024L * 1024L * 1024L) {
                "Kotlin BOOT runtime closure exceeds its aggregate bound"
            }
            JarFile(path.toFile(), true).use { jar ->
                require(jar.manifest?.mainAttributes?.getValue(Attributes.Name.CLASS_PATH) == null) {
                    "Kotlin BOOT runtime JAR contains a manifest Class-Path: $name"
                }
                require(jar.getJarEntry("META-INF/INDEX.LIST") == null) {
                    "Kotlin BOOT runtime JAR contains a class-path index: $name"
                }
                keeperClasses += jar.entries().asSequence().count {
                    !it.isDirectory &&
                        it.name == "decompengine/oracle/fulltree/KotlinSystemdCgroupBootKeeper.class"
                }
            }
            Triple(name, bytes, sha256(path))
        }
        require(keeperClasses == 1) {
            "Kotlin BOOT keeper class must occur exactly once in the deployment closure"
        }
        val encodedEntries = entries.joinToString(",\n", prefix = "[\n", postfix = "\n  ]") {
            (name, bytes, digest) ->
            "    {\n" +
                "      \"bytes\": $bytes,\n" +
                "      \"logicalName\": ${canonicalJsonString(name)},\n" +
                "      \"sha256\": \"$digest\"\n" +
                "    }"
        }
        val unsigned =
            "{\n" +
                "  \"entries\": $encodedEntries,\n" +
                "  \"provider\": \"gcc-kotlin-boot-deployment-classpath-reference-v1\",\n" +
                "  \"schemaVersion\": 1\n" +
                "}\n"
        val closureSha256 = MessageDigest.getInstance("SHA-256")
            .digest(unsigned.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte) }
        val reference =
            "{\n" +
                "  \"closureSha256\": \"$closureSha256\",\n" +
                "  \"entries\": $encodedEntries,\n" +
                "  \"provider\": \"gcc-kotlin-boot-deployment-classpath-reference-v1\",\n" +
                "  \"schemaVersion\": 1\n" +
                "}\n"
        val output = kotlinBootClasspathReference.get().asFile.toPath()
        Files.createDirectories(output.parent)
        Files.writeString(output, reference)
    }
}

val buildAcpGateHelper = tasks.register<Exec>("buildAcpGateHelper") {
    group = "build"
    description = "Builds the production static ACP sandbox gate helper"
    inputs.file(acpGateHelperSource)
    inputs.property("compiler", acpGateHelperCompiler)
    inputs.property("hostArchitecture", providers.systemProperty("os.arch"))
    outputs.file(acpGateHelperBinary)
    // A compiler upgrade is security-relevant but is not visible to Gradle's path-based inputs.
    outputs.upToDateWhen { false }

    doFirst {
        val osName = System.getProperty("os.name", "").lowercase()
        val architecture = System.getProperty("os.arch", "")
        require("linux" in osName && architecture in setOf("amd64", "x86_64", "aarch64")) {
            "the production ACP gate helper supports only Linux x86-64 or aarch64"
        }
        val configuredCompiler = file(acpGateHelperCompiler.get()).toPath().toAbsolutePath().normalize()
        val compiler = configuredCompiler.toRealPath()
        require(Files.isRegularFile(compiler, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(compiler)) {
            "ACP gate-helper compiler is not an executable regular file: $compiler"
        }
        val output = acpGateHelperBinary.get().asFile.toPath()
        Files.createDirectories(output.parent)
        commandLine(
            compiler.toString(),
            "-std=c11",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--build-id=none",
            acpGateHelperSource.asFile.absolutePath,
            "-o",
            output.toString(),
        )
    }
    doLast {
        Files.setPosixFilePermissions(
            acpGateHelperBinary.get().asFile.toPath(),
            PosixFilePermissions.fromString("rwxr-xr-x"),
        )
    }
}

val buildLlvmBehaviorHelper = tasks.register<Exec>("buildLlvmBehaviorHelper") {
    group = "build"
    description = "Builds the non-authoritative static LLVM behavior runtime helper prerequisite"
    inputs.file(llvmBehaviorHelperSource)
    inputs.property("compiler", llvmBehaviorHelperCompiler)
    inputs.property("hostArchitecture", providers.systemProperty("os.arch"))
    outputs.file(llvmBehaviorHelperBinary)
    // The compiler identity is security-relevant but is not represented by its configured path.
    outputs.upToDateWhen { false }

    doFirst {
        val osName = System.getProperty("os.name", "").lowercase()
        val architecture = System.getProperty("os.arch", "")
        require("linux" in osName && architecture in setOf("amd64", "x86_64", "aarch64")) {
            "the LLVM behavior helper supports only Linux x86-64 or aarch64"
        }
        val configuredCompiler = file(llvmBehaviorHelperCompiler.get()).toPath().toAbsolutePath().normalize()
        val compiler = configuredCompiler.toRealPath()
        require(Files.isRegularFile(compiler, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(compiler)) {
            "LLVM behavior-helper compiler is not an executable regular file: $compiler"
        }
        val output = llvmBehaviorHelperBinary.get().asFile.toPath()
        Files.createDirectories(output.parent)
        commandLine(
            compiler.toString(),
            "-std=c11",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wformat=2",
            "-Wl,--build-id=none",
            llvmBehaviorHelperSource.asFile.absolutePath,
            "-o",
            output.toString(),
        )
    }
    doLast {
        Files.setPosixFilePermissions(
            llvmBehaviorHelperBinary.get().asFile.toPath(),
            PosixFilePermissions.fromString("rwxr-xr-x"),
        )
    }
}

val verifyAcpGateHelper = tasks.register("verifyAcpGateHelper") {
    group = "verification"
    description = "Verifies the packaged ACP gate helper's static ELF and fail-closed contract"
    dependsOn(buildAcpGateHelper)
    inputs.file(acpGateHelperBinary)

    doLast {
        val helper = acpGateHelperBinary.get().asFile.toPath()
        val helperSize = Files.size(helper)
        require(helperSize in 64L..(4L * 1024 * 1024)) {
            "ACP gate helper must be a bounded ELF64 executable"
        }
        val bytes = Files.readAllBytes(helper)
        require(
            bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() &&
                bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte() &&
                bytes[4] == 2.toByte() && bytes[5] == 1.toByte(),
        ) { "ACP gate helper must be a little-endian ELF64 executable" }
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val expectedMachine = when (System.getProperty("os.arch", "")) {
            "amd64", "x86_64" -> 62
            "aarch64" -> 183
            else -> error("unsupported ACP gate-helper architecture")
        }
        require(elf.getShort(18).toInt() and 0xffff == expectedMachine) {
            "ACP gate-helper architecture does not match the build host"
        }
        val programOffset = elf.getLong(32)
        val programEntrySize = elf.getShort(54).toInt() and 0xffff
        val programCount = elf.getShort(56).toInt() and 0xffff
        require(programOffset >= 0 && programEntrySize >= 56 && programCount > 0) {
            "ACP gate helper has an invalid ELF program-header table"
        }
        repeat(programCount) { index ->
            val offset = Math.addExact(
                programOffset,
                Math.multiplyExact(index.toLong(), programEntrySize.toLong()),
            )
            require(offset <= bytes.size.toLong() - programEntrySize) {
                "ACP gate-helper program headers exceed the artifact"
            }
            when (elf.getInt(offset.toInt())) {
                3 -> error("ACP gate helper must not contain PT_INTERP")
                2 -> {
                    val dynamicOffset = elf.getLong(offset.toInt() + 8)
                    val dynamicSize = elf.getLong(offset.toInt() + 32)
                    require(
                        dynamicOffset >= 0 && dynamicSize >= 0 && dynamicSize % 16L == 0L &&
                            dynamicOffset <= bytes.size.toLong() - dynamicSize,
                    ) { "ACP gate-helper dynamic table is malformed" }
                    var cursor = dynamicOffset
                    var terminated = false
                    while (cursor < dynamicOffset + dynamicSize) {
                        when (elf.getLong(cursor.toInt())) {
                            0L -> {
                                terminated = true
                                break
                            }
                            1L -> error("ACP gate helper must not contain DT_NEEDED")
                        }
                        cursor += 16L
                    }
                    require(terminated) { "ACP gate-helper dynamic table is unterminated" }
                }
            }
        }
        val probe = ProcessBuilder(helper.toString()).also { builder ->
            builder.environment().clear()
        }.start()
        probe.outputStream.close()
        val exited = probe.waitFor(5, TimeUnit.SECONDS)
        if (!exited) {
            probe.destroyForcibly()
            probe.waitFor(2, TimeUnit.SECONDS)
        }
        require(exited && probe.exitValue() == 120) {
            "ACP gate helper did not fail closed on a missing protocol invocation"
        }
    }
}

val verifyLlvmBehaviorHelper = tasks.register("verifyLlvmBehaviorHelper") {
    group = "verification"
    description = "Verifies the LLVM behavior helper's static ELF and fail-closed v2 contract"
    dependsOn(buildLlvmBehaviorHelper)
    inputs.file(llvmBehaviorHelperBinary)

    doLast {
        val helper = llvmBehaviorHelperBinary.get().asFile.toPath()
        val helperSize = Files.size(helper)
        require(helperSize in 64L..(4L * 1024L * 1024L)) {
            "LLVM behavior helper must be a bounded ELF64 executable"
        }
        val bytes = Files.readAllBytes(helper)
        require(
            bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() &&
                bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte() &&
                bytes[4] == 2.toByte() && bytes[5] == 1.toByte(),
        ) { "LLVM behavior helper must be a little-endian ELF64 executable" }
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val expectedMachine = when (System.getProperty("os.arch", "")) {
            "amd64", "x86_64" -> 62
            "aarch64" -> 183
            else -> error("unsupported LLVM behavior-helper architecture")
        }
        require(elf.getShort(18).toInt() and 0xffff == expectedMachine) {
            "LLVM behavior-helper architecture does not match the build host"
        }
        val programOffset = elf.getLong(32)
        val programEntrySize = elf.getShort(54).toInt() and 0xffff
        val programCount = elf.getShort(56).toInt() and 0xffff
        require(programOffset >= 0 && programEntrySize >= 56 && programCount > 0) {
            "LLVM behavior helper has an invalid ELF program-header table"
        }
        var executableLoads = 0
        var stackRecords = 0
        repeat(programCount) { index ->
            val offset = Math.addExact(
                programOffset,
                Math.multiplyExact(index.toLong(), programEntrySize.toLong()),
            )
            require(offset <= bytes.size.toLong() - programEntrySize) {
                "LLVM behavior-helper program headers exceed the artifact"
            }
            val kind = elf.getInt(offset.toInt())
            val flags = elf.getInt(offset.toInt() + 4)
            when (kind) {
                1 -> {
                    require(flags and 3 != 3) {
                        "LLVM behavior helper contains a writable executable segment"
                    }
                    if (flags and 1 != 0) executableLoads++
                }
                3 -> error("LLVM behavior helper must not contain PT_INTERP")
                2 -> {
                    val dynamicOffset = elf.getLong(offset.toInt() + 8)
                    val dynamicSize = elf.getLong(offset.toInt() + 32)
                    require(
                        dynamicOffset >= 0 && dynamicSize >= 0 && dynamicSize % 16L == 0L &&
                            dynamicOffset <= bytes.size.toLong() - dynamicSize,
                    ) { "LLVM behavior-helper dynamic table is malformed" }
                    var cursor = dynamicOffset
                    var terminated = false
                    while (cursor < dynamicOffset + dynamicSize) {
                        when (elf.getLong(cursor.toInt())) {
                            0L -> {
                                terminated = true
                                break
                            }
                            1L -> error("LLVM behavior helper must not contain DT_NEEDED")
                        }
                        cursor += 16L
                    }
                    require(terminated) { "LLVM behavior-helper dynamic table is unterminated" }
                }
                0x6474e551 -> {
                    stackRecords++
                    require(flags and 1 == 0) { "LLVM behavior helper requests an executable stack" }
                }
            }
        }
        require(executableLoads > 0 && stackRecords == 1) {
            "LLVM behavior helper lacks its executable load or unique non-executable stack declaration"
        }
        require(bytes.toString(Charsets.ISO_8859_1).contains("decomp-llvm-behavior-helper-v2")) {
            "LLVM behavior helper omits its closed v2 protocol marker"
        }
        val probe = ProcessBuilder(helper.toString()).also { builder ->
            builder.environment().clear()
        }.start()
        probe.outputStream.close()
        val exited = probe.waitFor(5, TimeUnit.SECONDS)
        if (!exited) {
            probe.destroyForcibly()
            probe.waitFor(2, TimeUnit.SECONDS)
        }
        require(exited && probe.exitValue() == 125) {
            "LLVM behavior helper did not fail closed on a missing protocol invocation"
        }
    }
}

val generateAcpGateHelperChecksum = tasks.register("generateAcpGateHelperChecksum") {
    group = "distribution"
    description = "Writes the content digest shipped with the production ACP gate helper"
    dependsOn(verifyAcpGateHelper)
    inputs.file(acpGateHelperBinary)
    outputs.file(acpGateHelperChecksum)

    doLast {
        val helper = acpGateHelperBinary.get().asFile.toPath()
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(helper))
            .joinToString("") { byte -> "%02x".format(byte) }
        Files.writeString(
            acpGateHelperChecksum.get().asFile.toPath(),
            "$digest  decomp-acp-gate-helper\n",
        )
    }
}

val generateLlvmBehaviorHelperChecksum = tasks.register("generateLlvmBehaviorHelperChecksum") {
    group = "distribution"
    description = "Writes the digest shipped with the static LLVM behavior helper prerequisite"
    dependsOn(verifyLlvmBehaviorHelper)
    inputs.file(llvmBehaviorHelperBinary)
    outputs.file(llvmBehaviorHelperChecksum)

    doLast {
        val helper = llvmBehaviorHelperBinary.get().asFile.toPath()
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(helper))
            .joinToString("") { byte -> "%02x".format(byte) }
        Files.writeString(
            llvmBehaviorHelperChecksum.get().asFile.toPath(),
            "$digest  decomp-llvm-behavior-helper\n",
        )
    }
}

distributions {
    main {
        contents {
            from(acpGateHelperBinary) {
                into("libexec")
                filePermissions { unix("rwxr-xr-x") }
            }
            from(acpGateHelperChecksum) {
                into("libexec")
                filePermissions { unix("rw-r--r--") }
            }
            from(llvmBehaviorHelperBinary) {
                into("libexec")
                filePermissions { unix("rwxr-xr-x") }
            }
            from(llvmBehaviorHelperChecksum) {
                into("libexec")
                filePermissions { unix("rw-r--r--") }
            }
            from(kotlinBootClasspathReference) {
                into("lib")
                filePermissions { unix("rw-r--r--") }
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(generateAcpGateHelperChecksum)
    dependsOn(generateLlvmBehaviorHelperChecksum)
    dependsOn(generateKotlinBootClasspathReference)
    inputs.file(acpGateHelperBinary)
    inputs.file(acpGateHelperChecksum)
    inputs.file(llvmBehaviorHelperBinary)
    inputs.file(llvmBehaviorHelperChecksum)
    inputs.file(kotlinBootClasspathReference)
    inputs.dir(kotlinBootRuntimeDirectory)
    doFirst {
        systemProperty(
            "decompengine.acp.gateHelperExecutable",
            acpGateHelperBinary.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.acp.gateHelperChecksum",
            acpGateHelperChecksum.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.oracle.behavior.nativeHelperExecutable",
            llvmBehaviorHelperBinary.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.oracle.behavior.nativeHelperChecksum",
            llvmBehaviorHelperChecksum.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.oracle.gcc.bootKeeperClasspathReference",
            kotlinBootClasspathReference.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.oracle.gcc.bootKeeperClasspathRoot",
            kotlinBootRuntimeDirectory.get().asFile.absolutePath,
        )
    }
    environment(
        "DECOMP_ACP_PARENT_SECRET_CANARY",
        "decomp-acp-parent-secret-canary-must-not-cross-the-sandbox",
    )
}

dependencies {
    implementation("com.agentclientprotocol:acp:0.30.1")
    implementation("com.fasterxml.jackson.core:jackson-core:2.21.5")
    implementation("io.github.optimumcode:json-schema-validator:0.5.5")
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("org.bouncycastle:bcpg-jdk18on:1.85")
    implementation("org.bouncycastle:bcutil-jdk18on:1.85")
    implementation("org.bouncycastle:bcprov-jdk18on") {
        version { strictly("1.85.2") }
    }
    implementation("org.xerial:sqlite-jdbc:3.53.2.1")
    implementation("org.tukaani:xz:1.12")
    runtimeOnly("org.slf4j:slf4j-nop:2.0.16")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}

tasks.processResources {
    from("oracle") {
        include("**/*.schema.json")
        into("oracle")
    }
}

listOf("installDist", "distZip", "distTar").forEach { taskName ->
    tasks.named(taskName) {
        dependsOn(generateAcpGateHelperChecksum)
        dependsOn(generateLlvmBehaviorHelperChecksum)
        dependsOn(generateKotlinBootClasspathReference)
    }
}

val verifyAcpGateHelperDistribution = tasks.register("verifyAcpGateHelperDistribution") {
    group = "verification"
    description = "Verifies that installDist contains the production ACP gate helper and digest"
    dependsOn(tasks.named("installDist"))

    doLast {
        val root = layout.buildDirectory.dir("install/llm_bin_patch/libexec").get().asFile.toPath()
        val installedHelper = root.resolve("decomp-acp-gate-helper")
        val installedChecksum = root.resolve("decomp-acp-gate-helper.sha256")
        require(Files.isRegularFile(installedHelper, LinkOption.NOFOLLOW_LINKS)) {
            "installDist omitted the production ACP gate helper"
        }
        require(Files.isExecutable(installedHelper)) {
            "installDist removed the ACP gate-helper executable mode"
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(installedHelper))
            .joinToString("") { byte -> "%02x".format(byte) }
        require(Files.readString(installedChecksum) == "$digest  decomp-acp-gate-helper\n") {
            "installed ACP gate-helper digest does not authenticate the installed bytes"
        }
    }
}

val verifyLlvmBehaviorHelperDistribution = tasks.register("verifyLlvmBehaviorHelperDistribution") {
    group = "verification"
    description = "Verifies that installDist preserves the static LLVM behavior helper and digest"
    dependsOn(tasks.named("installDist"))

    doLast {
        val root = layout.buildDirectory.dir("install/llm_bin_patch/libexec").get().asFile.toPath()
        val installedHelper = root.resolve("decomp-llvm-behavior-helper")
        val installedChecksum = root.resolve("decomp-llvm-behavior-helper.sha256")
        require(Files.isRegularFile(installedHelper, LinkOption.NOFOLLOW_LINKS)) {
            "installDist omitted the LLVM behavior helper"
        }
        require(Files.isExecutable(installedHelper)) {
            "installDist removed the LLVM behavior-helper executable mode"
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(installedHelper))
            .joinToString("") { byte -> "%02x".format(byte) }
        require(Files.readString(installedChecksum) == "$digest  decomp-llvm-behavior-helper\n") {
            "installed LLVM behavior-helper digest does not authenticate the installed bytes"
        }
    }
}

val verifyKotlinBootClasspathDistribution = tasks.register("verifyKotlinBootClasspathDistribution") {
    group = "verification"
    description = "Verifies the installed Kotlin BOOT JVM closure against its external reference"
    dependsOn(tasks.named("installDist"))

    doLast {
        val installedRoot = layout.buildDirectory.dir("install/llm_bin_patch/lib").get().asFile.toPath()
        val stagedRoot = kotlinBootRuntimeDirectory.get().asFile.toPath()
        val referenceName = kotlinBootClasspathReference.get().asFile.name
        val installedReference = installedRoot.resolve(referenceName)
        require(
            Files.isRegularFile(installedReference, LinkOption.NOFOLLOW_LINKS) &&
                Files.readAllBytes(installedReference)
                    .contentEquals(Files.readAllBytes(kotlinBootClasspathReference.get().asFile.toPath())),
        ) { "installDist omitted or changed the Kotlin BOOT class-path reference" }
        val stagedNames = Files.list(stagedRoot).use { stream ->
            stream.map { it.fileName.toString() }.sorted().toList()
        }
        val installedJarNames = Files.list(installedRoot).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".jar") }
                .map { it.fileName.toString() }.sorted().toList()
        }
        require(installedJarNames == stagedNames) {
            "installDist Kotlin BOOT runtime JAR set differs from its staged reference"
        }
        stagedNames.forEach { name ->
            val staged = stagedRoot.resolve(name)
            val installed = installedRoot.resolve(name)
            require(
                Files.isRegularFile(installed, LinkOption.NOFOLLOW_LINKS) &&
                    Files.size(installed) == Files.size(staged) && sha256(installed) == sha256(staged),
            ) { "installDist changed Kotlin BOOT runtime entry $name" }
        }
    }
}

tasks.named("check") {
    dependsOn(verifyAcpGateHelperDistribution)
    dependsOn(verifyLlvmBehaviorHelperDistribution)
    dependsOn(verifyKotlinBootClasspathDistribution)
}
