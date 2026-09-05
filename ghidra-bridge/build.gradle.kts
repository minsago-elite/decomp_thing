import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.time.Duration

plugins { java }

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

val releaseName = "ghidra_12.1.3_PUBLIC"
val archiveName = "${releaseName}_20260817.zip"
val archiveSha256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
val archiveBytes = 569445154L
val cachedArchive = File(gradle.gradleUserHomeDir, "caches/decomp-ghidra/$archiveName")
val releaseDirectory = layout.buildDirectory.dir("release")
val ghidraDirectory = releaseDirectory.map { it.dir(releaseName) }

fun fileSha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(65536)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}

val fetchGhidra = tasks.register("fetchGhidra") {
    outputs.file(cachedArchive)
    outputs.upToDateWhen { false }
    doLast {
        fun validArchive() = cachedArchive.isFile && cachedArchive.length() == archiveBytes &&
            fileSha256(cachedArchive) == archiveSha256
        if (validArchive()) return@doLast
        check(!gradle.startParameter.isOffline) { "Offline build requires the hash-locked Ghidra archive at $cachedArchive" }
        cachedArchive.parentFile.mkdirs()
        val temporary = Files.createTempFile(cachedArchive.parentFile.toPath(), "ghidra-", ".download")
        try {
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL).build()
            val request = HttpRequest.newBuilder(URI.create(
                "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/$archiveName",
            )).timeout(Duration.ofMinutes(15)).build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
            response.body().use { input ->
                check(response.statusCode() == 200) { "Ghidra download failed: HTTP ${response.statusCode()}" }
                Files.newOutputStream(temporary).use { output ->
                    val buffer = ByteArray(65536)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        check(total <= archiveBytes) { "Ghidra archive exceeds pinned size" }
                        output.write(buffer, 0, count)
                    }
                }
            }
            check(temporary.toFile().length() == archiveBytes && fileSha256(temporary.toFile()) == archiveSha256) {
                "Ghidra archive does not match the pinned size and SHA-256"
            }
            Files.move(temporary, cachedArchive.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }
}

val unpackGhidra = tasks.register<Sync>("unpackGhidra") {
    dependsOn(fetchGhidra)
    from({ zipTree(cachedArchive) })
    into(releaseDirectory)
    includeEmptyDirs = true
    eachFile {
        require(relativePath.segments.first() == releaseName && relativePath.segments.none { it == ".." }) {
            "Unexpected Ghidra archive path: $relativePath"
        }
    }
}

val ghidraJars = files(provider {
    fileTree(ghidraDirectory) { include("Ghidra/**/lib/*.jar") }.files.sortedBy { it.path }
}).builtBy(unpackGhidra)

dependencies { compileOnly(ghidraJars) }

tasks.jar {
    archiveFileName.set("decomp-ghidra-bridge.jar")
    exclude("RunBundledExports.class")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

val stageBundle = tasks.register<Sync>("stageBundle") {
    dependsOn(unpackGhidra, tasks.jar)
    from(ghidraDirectory) { into(releaseName) }
    from(tasks.jar)
    from(tasks.compileJava.map { it.destinationDirectory }) {
        include("RunBundledExports.class")
        into("scripts")
    }
    into(layout.buildDirectory.dir("bundle"))
    includeEmptyDirs = true
    doLast {
        val root = destinationDir
        val records = root.walkTopDown().filter { it.isFile && it.name != "bundle.sha256" }
            .sortedBy { it.relativeTo(root).invariantSeparatorsPath }
            .joinToString("") { file -> "${fileSha256(file)}  ${file.relativeTo(root).invariantSeparatorsPath}\n" }
        root.resolve("bundle.sha256").writeText(records)
        val posix = Files.getFileStore(root.toPath()).supportsFileAttributeView("posix")
        root.walkTopDown().forEach { file ->
            if (file.isFile) check(file.setLastModified(315532800000L)) { "Could not normalize bundled Ghidra timestamp: $file" }
            if (posix) {
                val permissions = Files.getPosixFilePermissions(file.toPath()) -
                    setOf(PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE)
                Files.setPosixFilePermissions(file.toPath(), permissions)
            }
        }
    }
}
