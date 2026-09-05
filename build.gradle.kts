import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.Properties
import java.util.zip.ZipFile
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.Manifest

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

tasks.register<JavaExec>("generatedCRepairQualification") {
    group = "verification"
    description = "Runs the explicitly provisioned generated-C public-factory qualification driver"
    dependsOn("testClasses", "buildAcpGateHelper")
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("decompengine.project.GeneratedCRepairQualificationCli")
    doFirst {
        val action = requireNotNull(project.findProperty("generatedCQualificationAction") as? String)
        val output = requireNotNull(project.findProperty("generatedCQualificationOutput") as? String)
        args(action, output)
    }
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
    taskName = "generateFullTreeHeaderPlanReadiness",
    taskDescription = "Generates the incomplete authenticated A14 header-plan readiness envelope in Kotlin/JVM",
    entryPoint = "decompengine.oracle.fulltree.FullTreeHeaderPlanReadinessGeneratorCli",
)

registerOracleJavaExecTask(
    taskName = "generateFullTreeGeneratedFileInventory",
    taskDescription = "Validates an unreceipted A14 generated-file snapshot with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.fulltree.FullTreeGeneratedFileInventoryGeneratorCli",
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

registerOracleJavaExecTask(
    taskName = "generateLlvmBehaviorReferenceInputPlanV2",
    taskDescription = "Generates the Python-free LLVM behavior reference input plan with Kotlin/JVM authority",
    entryPoint = "decompengine.oracle.behavior.LlvmBehaviorReferenceInputPlanV2GeneratorCli",
).configure {
    args(layout.projectDirectory.file("oracle/llvm/22.1.6/behavior-reference-input-plan-v2.json").asFile.absolutePath)
}

registerOracleJavaExecTask(
    taskName = "generateLlvmBehaviorCandidateAcpLineageIndexV2",
    taskDescription = "Derives the immutable first-class ACP candidate lineage index from a verified archive",
    entryPoint = "decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Cli",
).configure {
    doFirst {
        val archive = requireNotNull(project.findProperty("candidateArchive") as? String) {
            "-PcandidateArchive=<absolute archive path> is required"
        }
        val output = requireNotNull(project.findProperty("candidateLineageIndex") as? String) {
            "-PcandidateLineageIndex=<absolute candidate-acp-lineage-index-v2.json path> is required"
        }
        args(archive, output)
    }
}

val acpGateHelperSource = layout.projectDirectory.file("src/main/c/decomp_acp_gate_helper.c")
val acpGateHelperBinary = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper")
val acpGateHelperChecksum = layout.buildDirectory.file("native/acp/decomp-acp-gate-helper.sha256")
val acpGateHelperCompiler = providers.gradleProperty("acpGateHelperCompiler").orElse("/usr/bin/cc")
val llvmBehaviorHelperSource = layout.projectDirectory.file("src/main/c/decomp_llvm_behavior_helper.c")
val llvmBehaviorHelperBinary = layout.buildDirectory.file("native/behavior/decomp-llvm-behavior-helper")
val llvmBehaviorHelperChecksum = layout.buildDirectory.file("native/behavior/decomp-llvm-behavior-helper.sha256")
val llvmBehaviorHelperCompiler = providers.gradleProperty("llvmBehaviorHelperCompiler").orElse("/usr/bin/cc")
val kotlinBootRuntimeDirectory = layout.buildDirectory.dir("oracle/gcc/kotlin-boot-runtime")
val oracleNativeLibraryDirectory = layout.buildDirectory.dir("native/oracle")
val oracleNativeLibraryPolicy = layout.projectDirectory.file("src/main/resources/oracle-native-libraries-v1.properties")
val stageOracleNativeLibraries = tasks.register("stageOracleNativeLibraries") {
    group = "build"
    description = "Stages hash-locked Linux x86-64 JNA and SQLite resources for noexec oracle scratch"
    inputs.file(oracleNativeLibraryPolicy)
    inputs.files(configurations.runtimeClasspath)
    outputs.dir(oracleNativeLibraryDirectory)
    doLast {
        val policy = Properties().apply { oracleNativeLibraryPolicy.asFile.inputStream().use(::load) }
        require(policy.getProperty("schemaVersion") == "1" && policy.getProperty("platform") == "linux-x86-64")
        val destination = oracleNativeLibraryDirectory.get().asFile.toPath()
        Files.createDirectories(destination)
        val posix = Files.getFileStore(destination).supportsFileAttributeView("posix")
        if (posix) Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("rwxr-xr-x"))
        listOf("jna", "sqlite").forEach { name ->
            val artifact = configurations.runtimeClasspath.get().single { it.name == policy.getProperty("$name.artifact") }
            require(sha256(artifact.toPath()) == policy.getProperty("$name.artifactSha256")) { "Oracle native dependency JAR changed: $name" }
            ZipFile(artifact).use { archive ->
                val resourceName = policy.getProperty("$name.resource")
                val entries = archive.entries().asSequence().filter { it.name == resourceName }.toList()
                require(entries.size == 1 && !entries.single().isDirectory) { "Oracle native JAR resource is missing or ambiguous: $name" }
                val entry = entries.single()
                val expectedBytes = policy.getProperty("$name.bytes").toLong()
                require(expectedBytes in 1..(16L * 1024 * 1024) && entry.size == expectedBytes)
                val bytes = archive.getInputStream(entry).use { it.readNBytes(expectedBytes.toInt() + 1) }
                require(bytes.size.toLong() == expectedBytes)
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { byte -> "%02x".format(byte) }
                require(digest == policy.getProperty("$name.sha256")) { "Oracle native resource digest changed: $name" }
                val output = Files.write(destination.resolve(policy.getProperty("$name.name")), bytes)
                if (posix) Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-r--r--"))
            }
        }
    }
}
val kotlinBootClasspathReference =
    layout.buildDirectory.file("generated/oracle/gcc/kotlin-boot-classpath-reference-v1.json")
val llvmHostedWorkerClasspathReference =
    layout.buildDirectory.file(
        "generated/oracle/behavior/llvm-behavior-hosted-worker-classpath-reference-v1.json",
    )

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

fun littleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
    (bytes[offset].toLong() and 0xffL) or
        ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
        ((bytes[offset + 2].toLong() and 0xffL) shl 16) or
        ((bytes[offset + 3].toLong() and 0xffL) shl 24)

fun readChannelRange(
    channel: java.nio.channels.SeekableByteChannel,
    position: Long,
    length: Int,
    label: String,
): ByteArray {
    val bytes = ByteArray(length)
    channel.position(position)
    val buffer = ByteBuffer.wrap(bytes)
    while (buffer.hasRemaining()) require(channel.read(buffer) > 0) { "$label ended during bounded reading" }
    return bytes
}

fun requireClassicZipExtraFields(extra: ByteArray, path: java.nio.file.Path) {
    var cursor = 0
    while (cursor < extra.size) {
        require(extra.size - cursor >= 4) { "JAR has a truncated ZIP extra field: $path" }
        val identifier = littleEndianUnsignedShort(extra, cursor)
        val valueBytes = littleEndianUnsignedShort(extra, cursor + 2)
        val next = Math.addExact(cursor, Math.addExact(4, valueBytes))
        require(next <= extra.size) { "JAR has a truncated ZIP extra field: $path" }
        require(identifier != 0x0001) { "JAR contains ZIP64 metadata: $path" }
        cursor = next
    }
}

fun scanClassicCentralDirectory(
    path: java.nio.file.Path,
    centralOffset: Long,
    centralBytes: Long,
    remainingEntries: Int,
): Int = Files.newByteChannel(path).use { channel ->
    val centralEnd = Math.addExact(centralOffset, centralBytes)
    var cursor = centralOffset
    var count = 0
    while (cursor < centralEnd) {
        require(centralEnd - cursor >= 46L) { "JAR has a truncated central-directory record: $path" }
        val header = readChannelRange(channel, cursor, 46, "JAR central-directory header: $path")
        require(littleEndianUnsignedInt(header, 0) == 0x02014b50L) {
            "JAR has an invalid central-directory signature: $path"
        }
        val compressedBytes = littleEndianUnsignedInt(header, 20)
        val uncompressedBytes = littleEndianUnsignedInt(header, 24)
        val nameBytes = littleEndianUnsignedShort(header, 28)
        val extraBytes = littleEndianUnsignedShort(header, 30)
        val commentBytes = littleEndianUnsignedShort(header, 32)
        val startDisk = littleEndianUnsignedShort(header, 34)
        val localHeaderOffset = littleEndianUnsignedInt(header, 42)
        require(
            nameBytes > 0 && startDisk == 0 && compressedBytes != 0xffff_ffffL &&
                uncompressedBytes != 0xffff_ffffL && localHeaderOffset != 0xffff_ffffL &&
                localHeaderOffset < centralOffset,
        ) { "JAR contains a non-classic central-directory record: $path" }
        val recordBytes = Math.addExact(
            46L,
            Math.addExact(nameBytes.toLong(), Math.addExact(extraBytes.toLong(), commentBytes.toLong())),
        )
        val next = Math.addExact(cursor, recordBytes)
        require(next <= centralEnd) { "JAR has a truncated central-directory record: $path" }
        if (extraBytes > 0) {
            val extra = readChannelRange(
                channel,
                cursor + 46L + nameBytes,
                extraBytes,
                "JAR central-directory extra fields: $path",
            )
            requireClassicZipExtraFields(extra, path)
        }
        require(count < 100_000 && count < remainingEntries) {
            "JAR exceeds its central-directory entry bound: $path"
        }
        count += 1
        cursor = next
    }
    require(cursor == centralEnd && count > 0) { "JAR has an invalid central-directory extent: $path" }
    count
}

fun preflightClassicJar(path: java.nio.file.Path, remainingEntries: Int): Int {
    val fileBytes = Files.size(path)
    require(fileBytes >= 22L && remainingEntries > 0) { "JAR lacks a bounded classic ZIP directory: $path" }
    val tailBytes = minOf(fileBytes, 65_557L).toInt()
    val tailOffset = fileBytes - tailBytes
    val tail = ByteArray(tailBytes)
    Files.newByteChannel(path).use { channel ->
        channel.position(tailOffset)
        val buffer = ByteBuffer.wrap(tail)
        while (buffer.hasRemaining()) require(channel.read(buffer) > 0) { "JAR ended during ZIP preflight: $path" }
    }
    var endOffset = -1
    for (candidate in tail.size - 22 downTo 0) {
        if (littleEndianUnsignedInt(tail, candidate) != 0x06054b50L) continue
        val commentBytes = littleEndianUnsignedShort(tail, candidate + 20)
        if (candidate + 22 + commentBytes == tail.size) {
            endOffset = candidate
            break
        }
    }
    require(endOffset >= 0) { "JAR lacks a bounded classic ZIP end: $path" }
    val absoluteEndOffset = tailOffset + endOffset
    if (absoluteEndOffset >= 20L) {
        val locator = ByteArray(20)
        Files.newByteChannel(path).use { channel ->
            channel.position(absoluteEndOffset - 20L)
            val buffer = ByteBuffer.wrap(locator)
            while (buffer.hasRemaining()) require(channel.read(buffer) > 0) {
                "JAR ended during ZIP64 locator preflight: $path"
            }
        }
        require(littleEndianUnsignedInt(locator, 0) != 0x07064b50L) {
            "JAR contains a ZIP64 end locator: $path"
        }
    }
    val disk = littleEndianUnsignedShort(tail, endOffset + 4)
    val centralDisk = littleEndianUnsignedShort(tail, endOffset + 6)
    val diskEntries = littleEndianUnsignedShort(tail, endOffset + 8)
    val totalEntries = littleEndianUnsignedShort(tail, endOffset + 10)
    val centralBytes = littleEndianUnsignedInt(tail, endOffset + 12)
    val centralOffset = littleEndianUnsignedInt(tail, endOffset + 16)
    require(
        disk == 0 && centralDisk == 0 && diskEntries == totalEntries && totalEntries != 0xffff &&
            centralBytes != 0xffff_ffffL && centralOffset != 0xffff_ffffL,
    ) { "JAR requires unsupported ZIP64 or split ZIP: $path" }
    require(
        totalEntries in 1..minOf(100_000, remainingEntries) &&
            centralBytes in 1L..(64L * 1024L * 1024L) &&
            centralOffset + centralBytes == absoluteEndOffset,
    ) { "JAR exceeds its canonical central-directory bound: $path" }
    val scannedEntries = scanClassicCentralDirectory(path, centralOffset, centralBytes, remainingEntries)
    require(scannedEntries == diskEntries && scannedEntries == totalEntries) {
        "JAR central-directory count differs from its ZIP end: $path"
    }
    return scannedEntries
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
        require(names.all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,250}\\.jar")) }) {
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

val generateLlvmHostedWorkerClasspathReference = tasks.register("generateLlvmHostedWorkerClasspathReference") {
    group = "distribution"
    description = "Generates the deployment reference for the fixed LLVM hosted-worker JVM closure"
    dependsOn(stageKotlinBootRuntime)
    inputs.dir(kotlinBootRuntimeDirectory)
    outputs.file(llvmHostedWorkerClasspathReference)

    doLast {
        val runtimeRoot = kotlinBootRuntimeDirectory.get().asFile.toPath()
        val mainName = tasks.named<Jar>("jar").get().archiveFile.get().asFile.name
        val dependencyNames = configurations.runtimeClasspath.get().files.map { it.name }.sorted()
        val names = listOf(mainName) + dependencyNames
        require(names.size in 1..512 && names.toSet().size == names.size) {
            "LLVM hosted-worker runtime closure has duplicate or excessive logical JAR names"
        }
        require(names.all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,250}\\.jar")) }) {
            "LLVM hosted-worker runtime closure contains an unsafe logical JAR name"
        }
        val stagedNames = Files.list(runtimeRoot).use { stream ->
            stream.map { it.fileName.toString() }.sorted().toList()
        }
        require(stagedNames == names.sorted()) {
            "staged LLVM hosted-worker runtime differs from the exact reference input set"
        }
        var totalBytes = 0L
        var workerMainClasses = 0
        var workerMainJarIndex = -1
        var totalJarEntries = 0
        val entries = names.mapIndexed { index, name ->
            val path = runtimeRoot.resolve(name)
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                "LLVM hosted-worker runtime entry is not a regular JAR: $name"
            }
            val bytes = Files.size(path)
            require(bytes in 1L..(1024L * 1024L * 1024L)) {
                "LLVM hosted-worker runtime JAR exceeds its per-entry bound: $name"
            }
            totalBytes = Math.addExact(totalBytes, bytes)
            require(totalBytes <= 2L * 1024L * 1024L * 1024L) {
                "LLVM hosted-worker runtime closure exceeds its aggregate bound"
            }
            val preflightEntries = preflightClassicJar(path, 500_000 - totalJarEntries)
            // The generated SHA sidecar owns byte authentication; disable implicit signature
            // verifier reads so only the explicitly bounded manifest is inflated here.
            JarFile(path.toFile(), false).use { jar ->
                require(jar.size() == preflightEntries) {
                    "LLVM hosted-worker runtime JAR central directory changed: $name"
                }
                totalJarEntries += preflightEntries
                val workerMain =
                    "decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2InnerWorkerMain.class"
                var visited = 0
                var manifestEntry: JarEntry? = null
                jar.entries().asSequence().forEach { entry ->
                    visited += 1
                    if (!entry.isDirectory && entry.name.equals(JarFile.MANIFEST_NAME, ignoreCase = true)) {
                        require(manifestEntry == null) {
                            "LLVM hosted-worker runtime JAR contains duplicate manifests: $name"
                        }
                        manifestEntry = entry
                    }
                    require(entry.isDirectory || !entry.name.equals("META-INF/INDEX.LIST", ignoreCase = true)) {
                        "LLVM hosted-worker runtime JAR contains a class-path index: $name"
                    }
                    if (!entry.isDirectory && entry.name == workerMain) {
                        workerMainClasses += 1
                        workerMainJarIndex = index
                    }
                    require(
                        entry.isDirectory ||
                            !Regex("META-INF/versions/[1-9][0-9]*/${Regex.escape(workerMain)}")
                                .matches(entry.name),
                    ) {
                        "LLVM hosted-worker runtime JAR contains a versioned worker main class: $name"
                    }
                }
                require(visited == preflightEntries) {
                    "LLVM hosted-worker runtime JAR central directory changed: $name"
                }
                manifestEntry?.let { entry ->
                    require(entry.size in 0L..(2L * 1024L * 1024L) &&
                        entry.compressedSize in 0L..(2L * 1024L * 1024L)
                    ) {
                        "LLVM hosted-worker runtime JAR manifest exceeds its byte bound: $name"
                    }
                    val manifestBytes = jar.getInputStream(entry).use { input ->
                        input.readNBytes(2 * 1024 * 1024 + 1)
                    }
                    require(manifestBytes.size.toLong() == entry.size && manifestBytes.size <= 2 * 1024 * 1024) {
                        "LLVM hosted-worker runtime JAR manifest changed length: $name"
                    }
                    require(Manifest(manifestBytes.inputStream()).mainAttributes
                        .getValue(Attributes.Name.CLASS_PATH) == null
                    ) {
                        "LLVM hosted-worker runtime JAR contains a manifest Class-Path: $name"
                    }
                }
            }
            Triple(name, bytes, sha256(path))
        }
        require(workerMainClasses == 1) {
            "LLVM hosted-worker main class must occur exactly once in the deployment closure"
        }
        require(workerMainJarIndex == 0) {
            "LLVM hosted-worker main class must occur in the first deployment JAR"
        }
        val encodedEntries = entries.joinToString(",\n", prefix = "[\n", postfix = "\n  ]") {
            (name, bytes, digest) ->
            "    {\n" +
                "      \"bytes\": $bytes,\n" +
                "      \"logicalName\": ${canonicalJsonString(name)},\n" +
                "      \"sha256\": \"$digest\"\n" +
                "    }"
        }
        val provider = "llvm-behavior-hosted-worker-deployment-classpath-reference-v1"
        val unsigned =
            "{\n" +
                "  \"entries\": $encodedEntries,\n" +
                "  \"provider\": \"$provider\",\n" +
                "  \"schemaVersion\": 1\n" +
                "}\n"
        val closureSha256 = MessageDigest.getInstance("SHA-256")
            .digest(unsigned.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte) }
        val reference =
            "{\n" +
                "  \"closureSha256\": \"$closureSha256\",\n" +
                "  \"entries\": $encodedEntries,\n" +
                "  \"provider\": \"$provider\",\n" +
                "  \"schemaVersion\": 1\n" +
                "}\n"
        val output = llvmHostedWorkerClasspathReference.get().asFile.toPath()
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
            from(llvmHostedWorkerClasspathReference) {
                into("lib")
                filePermissions { unix("rw-r--r--") }
            }
            from(project(":ghidra-bridge").layout.buildDirectory.dir("bundle")) {
                into("libexec/ghidra")
                eachFile {
                    val normalizedMode = if (file.canExecute()) 0x1ed else 0x1a4
                    permissions { unix(normalizedMode) }
                }
            }
            from(oracleNativeLibraryDirectory) {
                into("libexec/oracle-native")
                filePermissions { unix("rw-r--r--") }
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(stageOracleNativeLibraries)
    dependsOn(":ghidra-bridge:stageBundle")
    val testInstalledGhidra = providers.environmentVariable("RUN_REAL_GHIDRA").orNull == "true" ||
        providers.environmentVariable("RUN_REAL_GHIDRA_CALL_SITES").orNull == "true"
    if (testInstalledGhidra) dependsOn("installDist")
    dependsOn(generateAcpGateHelperChecksum)
    dependsOn(generateLlvmBehaviorHelperChecksum)
    dependsOn(generateKotlinBootClasspathReference)
    dependsOn(generateLlvmHostedWorkerClasspathReference)
    inputs.file(acpGateHelperBinary)
    inputs.file(acpGateHelperChecksum)
    inputs.file(llvmBehaviorHelperBinary)
    inputs.file(llvmBehaviorHelperChecksum)
    inputs.file(kotlinBootClasspathReference)
    inputs.file(llvmHostedWorkerClasspathReference)
    inputs.dir(kotlinBootRuntimeDirectory)
    doFirst {
        systemProperty("decompengine.oracle.nativeLibraryDirectory", oracleNativeLibraryDirectory.get().asFile.absolutePath)
        val ghidraBundle = if (testInstalledGhidra) layout.buildDirectory.dir("install/llm_bin_patch/libexec/ghidra")
            else project(":ghidra-bridge").layout.buildDirectory.dir("bundle")
        systemProperty("decompengine.ghidra.bundle", ghidraBundle.get().asFile.absolutePath)
        systemProperty("decompengine.ghidra.provenanceArchive", File(gradle.gradleUserHomeDir,
            "caches/decomp-ghidra/ghidra_12.1.3_PUBLIC_20260817.zip").absolutePath)
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
        systemProperty(
            "decompengine.oracle.behavior.hostedWorkerClasspathReference",
            llvmHostedWorkerClasspathReference.get().asFile.absolutePath,
        )
        systemProperty(
            "decompengine.oracle.behavior.hostedWorkerClasspathRoot",
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
    testImplementation("org.apache.commons:commons-compress:1.28.0")
}

tasks.processResources {
    from("oracle") {
        include("**/*.schema.json")
        into("oracle")
    }
}

listOf("installDist", "distZip", "distTar").forEach { taskName ->
    tasks.named(taskName) {
        dependsOn(":ghidra-bridge:stageBundle")
        dependsOn(stageOracleNativeLibraries)
        inputs.property("ghidraBundlePermissionsVersion", 2)
        dependsOn(generateAcpGateHelperChecksum)
        dependsOn(generateLlvmBehaviorHelperChecksum)
        dependsOn(generateKotlinBootClasspathReference)
        dependsOn(generateLlvmHostedWorkerClasspathReference)
    }
}

tasks.named<JavaExec>("run") {
    dependsOn(":ghidra-bridge:stageBundle")
    systemProperty("decompengine.ghidra.bundle", project(":ghidra-bridge").layout.buildDirectory.dir("bundle").get().asFile.absolutePath)
}

tasks.named<Sync>("installDist") {
    doLast {
        destinationDir.resolve("libexec/ghidra").walkTopDown().filter { it.isFile }.forEach { file ->
            check(file.setLastModified(315532800000L)) { "Could not normalize installed Ghidra timestamp: $file" }
        }
    }
}

tasks.register("verifyGhidraDistributionArchives") {
    group = "verification"
    description = "Verifies complete bundled Ghidra bytes and executable modes in ZIP and TAR distributions"
    dependsOn("distZip", "distTar")
    doLast {
        fun digest(input: java.io.InputStream): String {
            val hash = MessageDigest.getInstance("SHA-256")
            input.use { stream ->
                val buffer = ByteArray(65536)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    hash.update(buffer, 0, count)
                }
            }
            return hash.digest().joinToString("") { byte -> "%02x".format(byte) }
        }
        val staged = project(":ghidra-bridge").layout.buildDirectory.dir("bundle").get().asFile
        val manifest = staged.resolve("bundle.sha256")
        val expected = manifest.readLines().associate { it.substring(66) to it.substring(0, 64) } +
            ("bundle.sha256" to digest(manifest.inputStream()))
        val prefix = "llm_bin_patch-$version/libexec/ghidra/"
        val archiveTrees = listOf(
            zipTree(tasks.named<Zip>("distZip").get().archiveFile),
            tarTree(tasks.named<Tar>("distTar").get().archiveFile),
        )
        archiveTrees.forEach { tree ->
            val observed = mutableSetOf<String>()
            tree.visit {
                if (!isDirectory && path.startsWith(prefix)) {
                    val relative = path.removePrefix(prefix)
                    require(observed.add(relative) && relative in expected) { "Unexpected Ghidra archive member: $relative" }
                    require(digest(open()) == expected.getValue(relative)) { "Changed Ghidra archive member: $relative" }
                    val expectedMode = if (staged.resolve(relative).canExecute()) 0x1ed else 0x1a4
                    require(permissions.toUnixNumeric() == expectedMode) { "Lost Ghidra archive permissions: $relative" }
                }
            }
            require(observed == expected.keys) { "Distribution omits bundled Ghidra files" }
        }
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
        val installedLlvmReference = installedRoot.resolve(llvmHostedWorkerClasspathReference.get().asFile.name)
        require(
            Files.isRegularFile(installedLlvmReference, LinkOption.NOFOLLOW_LINKS) &&
                Files.readAllBytes(installedLlvmReference)
                    .contentEquals(Files.readAllBytes(llvmHostedWorkerClasspathReference.get().asFile.toPath())),
        ) { "installDist omitted or changed the LLVM hosted-worker class-path reference" }
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
