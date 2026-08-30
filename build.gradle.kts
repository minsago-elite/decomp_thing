import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

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

val acpGateHelperSource = layout.projectDirectory.file("src/main/c/decomp_acp_gate_helper.c")
val acpGateHelperBinary = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper")
val acpGateHelperChecksum = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper.sha256")
val acpGateHelperCompiler = providers.gradleProperty("acpGateHelperCompiler").orElse("/usr/bin/cc")

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
        }
    }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(generateAcpGateHelperChecksum)
    inputs.file(acpGateHelperBinary)
    inputs.file(acpGateHelperChecksum)
    doFirst {
        systemProperty(
            "decompengine.acp.gateHelperExecutable",
            acpGateHelperBinary.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.acp.gateHelperChecksum",
            acpGateHelperChecksum.get().asFile.absolutePath,
        )
    }
    environment(
        "DECOMP_ACP_PARENT_SECRET_CANARY",
        "decomp-acp-parent-secret-canary-must-not-cross-the-sandbox",
    )
}

dependencies {
    implementation("com.agentclientprotocol:acp:0.30.1")
    implementation("io.github.optimumcode:json-schema-validator:0.5.5")
    implementation("net.java.dev.jna:jna:5.19.1")
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

tasks.named("check") {
    dependsOn(verifyAcpGateHelperDistribution)
}
