package decompengine.git

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.Base64

/** The documented remote transports (#585). Anything else is refused before Git runs. */
enum class GitTransport(val wireName: String) { HTTPS("https"), SSH("ssh"), ADMITTED("admitted") }

/**
 * A remote location after policy checks. [url] is what Git receives; it never holds a secret.
 * [display] is safe for any client: admitted local remotes show their admitted name, never a
 * host path.
 */
data class GitRemoteLocation(val transport: GitTransport, val url: String, val host: String?, val display: String)

/** Bounds for one network transfer (#592, #593). */
data class GitTransferLimits(
    val timeout: Duration = Duration.ofMinutes(10),
    val maxRepositoryBytes: Long = 2L * 1024 * 1024 * 1024,
    val maxProgressMessages: Int = 1,
) {
    init { require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofMinutes(10) && maxRepositoryBytes > 0) }
}

/** One operator-configured credential. Secret material stays in its file and is read only at use time. */
sealed interface GitCredential {
    val host: String

    data class Https(override val host: String, val username: String, val passwordFile: Path, val caFile: Path?) : GitCredential {
        override fun toString() = "GitCredential.Https($host)"
    }

    data class Ssh(override val host: String, val identityFile: Path?, val knownHostsFile: Path) : GitCredential {
        override fun toString() = "GitCredential.Ssh($host)"
    }
}

/**
 * Server-side credentials for remote hosts (#586). Loaded from an operator file; the browser only
 * ever learns whether a remote has a configured credential.
 *
 * ```json
 * {"https": [{"host": "git.example.org", "username": "bot", "passwordFile": "/etc/decomp/git-token", "caFile": null}],
 *  "ssh":   [{"host": "git.example.org", "identityFile": "/etc/decomp/id_ed25519", "knownHostsFile": "/etc/decomp/known_hosts"}]}
 * ```
 */
class GitCredentialStore(entries: List<GitCredential>) {
    private val https = entries.filterIsInstance<GitCredential.Https>().associateBy { it.host }
    private val ssh = entries.filterIsInstance<GitCredential.Ssh>().associateBy { it.host }

    fun https(host: String): GitCredential.Https? = https[host]
    fun ssh(host: String): GitCredential.Ssh? = ssh[host]

    /** `configured`, `none` or `not-required`; never the credential itself. */
    fun describe(location: GitRemoteLocation): String = when (location.transport) {
        GitTransport.ADMITTED -> "not-required"
        GitTransport.HTTPS -> if (location.host?.let(::https) != null) "configured" else "none"
        GitTransport.SSH -> if (location.host?.let(::ssh)?.identityFile != null) "configured" else "none"
    }

    override fun toString() = "GitCredentialStore(${https.size + ssh.size} entries)"

    companion object {
        val EMPTY = GitCredentialStore(emptyList())

        fun load(file: Path): GitCredentialStore {
            val value = try {
                Json.parseToJsonElement(GitStorage.read(file, 64 * 1024).toString(Charsets.UTF_8)).jsonObject
            } catch (_: Exception) { throw IllegalArgumentException("The Git credential file is unreadable or not JSON.") }
            require(value.keys.all { it in setOf("https", "ssh") }) { "The Git credential file has unknown sections." }
            fun path(entry: JsonObject, name: String, required: Boolean): Path? {
                val raw = entry[name]?.takeIf { it != JsonNull }?.jsonPrimitive?.content
                if (raw == null) { require(!required) { "A Git credential entry needs $name." }; return null }
                val path = Path.of(raw)
                require(path.isAbsolute && Files.isRegularFile(path)) { "A Git credential file path must name an existing absolute file." }
                return path
            }
            fun host(entry: JsonObject): String = entry.getValue("host").jsonPrimitive.content.lowercase().also {
                require(GitRemoteUrls.isHost(it)) { "A Git credential host is invalid." }
            }
            val entries = buildList {
                value["https"]?.jsonArray?.forEach { item ->
                    val entry = item.jsonObject
                    require(entry.keys.all { it in setOf("host", "username", "passwordFile", "caFile") })
                    val username = entry.getValue("username").jsonPrimitive.content
                    require(username.matches(Regex("[A-Za-z0-9._@+-]{1,128}"))) { "A Git credential username is invalid." }
                    add(GitCredential.Https(host(entry), username, checkNotNull(path(entry, "passwordFile", true)), path(entry, "caFile", false)))
                }
                value["ssh"]?.jsonArray?.forEach { item ->
                    val entry = item.jsonObject
                    require(entry.keys.all { it in setOf("host", "identityFile", "knownHostsFile") })
                    add(GitCredential.Ssh(host(entry), path(entry, "identityFile", false), checkNotNull(path(entry, "knownHostsFile", true))))
                }
            }
            require(entries.groupBy { it::class to it.host }.values.all { it.size == 1 }) { "A Git credential host is listed twice." }
            return GitCredentialStore(entries)
        }
    }
}

/** Operator policy for remotes (#585, #586). Everything is closed unless configured. */
data class GitRemotePolicy(
    /** Exact lowercase host names that HTTPS and SSH remotes may name. */
    val allowedHosts: Set<String> = emptySet(),
    /** Directory whose immediate children are admitted local remotes, named `admitted:<name>`. */
    val admittedRoot: Path? = null,
    val credentials: GitCredentialStore = GitCredentialStore.EMPTY,
    val limits: GitTransferLimits = GitTransferLimits(),
) {
    init { require(allowedHosts.all(GitRemoteUrls::isHost)) }
    val configured: Boolean get() = allowedHosts.isNotEmpty() || admittedRoot != null
}

/** URL policy: documented transports, allowlisted destinations, no embedded secrets (#585). */
object GitRemoteUrls {
    private val HOST = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
    private val USER = Regex("[A-Za-z0-9._][A-Za-z0-9._-]{0,63}")
    private val NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

    fun isHost(value: String) = value.length <= 253 && HOST.matches(value)

    private fun refuse(code: String, message: String): Nothing = throw GitOperationRefusal(code, message)

    fun parse(raw: String, policy: GitRemotePolicy): GitRemoteLocation {
        if (raw.isEmpty() || raw.length > 2048 || raw.any { it.code <= 0x20 || it.code == 0x7f || it == '\\' }) {
            refuse("VALIDATION_FAILED", "A remote URL is 1 to 2048 visible characters without spaces or backslashes.")
        }
        // `<transport>::<address>` runs a remote helper program (ext::, fd:: and others).
        if (Regex("^[A-Za-z][A-Za-z0-9+.-]*::").containsMatchIn(raw)) {
            refuse("TRANSPORT_UNSUPPORTED", "Remote helper URLs are not allowed. Use an https://, ssh:// or admitted remote.")
        }
        if (raw.startsWith("admitted:")) {
            val name = raw.removePrefix("admitted:")
            val root = policy.admittedRoot ?: refuse("TRANSPORT_UNSUPPORTED", "No admitted local remotes are configured on this server.")
            if (!NAME.matches(name)) refuse("VALIDATION_FAILED", "An admitted remote is named admitted:<name>.")
            val directory = root.resolve(name)
            if (directory.parent != root || !Files.isDirectory(directory, NOFOLLOW_LINKS)) {
                refuse("DESTINATION_NOT_ALLOWED", "No admitted local remote has that name.")
            }
            requireContainedRepository(directory)
            return GitRemoteLocation(GitTransport.ADMITTED, "file://${directory.toRealPath()}", null, "admitted:$name")
        }
        val scheme = Regex("^([A-Za-z][A-Za-z0-9+.-]*)://").find(raw)?.groupValues?.get(1)?.lowercase()
        if (scheme == null) {
            // scp-like `[user@]host:path`; a bare path or a colon-free value is a host filesystem path.
            val match = Regex("^(?:([^@/:]+)@)?([^@/:]+):(.+)$").matchEntire(raw)
                ?: refuse("TRANSPORT_UNSUPPORTED", "Local filesystem paths are not allowed. Use an https://, ssh:// or admitted remote.")
            val (user, host, path) = match.destructured
            if (path.startsWith("-")) refuse("VALIDATION_FAILED", "The SSH repository path cannot start with -.")
            return ssh(user.ifEmpty { null }, host.lowercase(), null, if (path.startsWith("/")) path else "/~/$path", policy)
        }
        if (scheme !in setOf("https", "ssh")) {
            refuse("TRANSPORT_UNSUPPORTED", "Only https://, ssh:// and admitted remotes are supported; $scheme:// is not.")
        }
        val uri = try { URI(raw) } catch (_: URISyntaxException) { refuse("VALIDATION_FAILED", "The remote URL is malformed.") }
        if (uri.rawQuery != null || uri.rawFragment != null) refuse("VALIDATION_FAILED", "Remote URLs cannot carry a query or fragment.")
        val host = uri.host?.lowercase() ?: refuse("VALIDATION_FAILED", "The remote URL needs a host name.")
        val path = uri.rawPath?.takeIf { it.length > 1 } ?: refuse("VALIDATION_FAILED", "The remote URL needs a repository path.")
        if (path.split('/').any { it == ".." }) refuse("VALIDATION_FAILED", "Remote paths cannot contain '..'.")
        return when (scheme) {
            "https" -> {
                if (uri.rawUserInfo != null) refuse("CREDENTIAL_IN_URL",
                    "Remote URLs must not embed a user name, password or token. Credentials are configured on the server.")
                allowed(host, policy)
                val port = if (uri.port == -1) "" else ":${uri.port}"
                GitRemoteLocation(GitTransport.HTTPS, "https://$host$port$path", host, "https://$host$port$path")
            }
            "ssh" -> {
                val info = uri.rawUserInfo
                if (info != null && ':' in info) refuse("CREDENTIAL_IN_URL", "Remote URLs must not embed a password.")
                ssh(info, host, uri.port.takeIf { it != -1 }, path, policy)
            }
            else -> refuse("TRANSPORT_UNSUPPORTED", "Only https://, ssh:// and admitted remotes are supported; $scheme:// is not.")
        }
    }

    /**
     * File transport follows repository metadata independently of the admitted directory. Reject
     * indirect layouts before Git sees them, including links anywhere in objects/refs (not just
     * the immediate .git entry). Like local import, alternates and linked worktrees are unsupported.
     * Operator-owned admitted repositories must not be modified concurrently with a transfer.
     */
    private fun requireContainedRepository(directory: Path) {
        fun denied(): Nothing = refuse("DESTINATION_NOT_ALLOWED", "The admitted remote must be a self-contained repository without links, gitfiles or alternates.")
        try {
            val dotGit = directory.resolve(".git")
            val gitDir = when {
                Files.isDirectory(dotGit, NOFOLLOW_LINKS) -> dotGit
                Files.exists(dotGit, NOFOLLOW_LINKS) -> denied()
                else -> directory
            }
            if (!Files.isRegularFile(gitDir.resolve("HEAD"), NOFOLLOW_LINKS) ||
                !Files.isDirectory(gitDir.resolve("objects"), NOFOLLOW_LINKS) || !Files.isDirectory(gitDir.resolve("refs"), NOFOLLOW_LINKS)) denied()
            for (path in listOf("commondir", "shallow", "objects/info/alternates", "objects/info/http-alternates")) {
                if (Files.exists(gitDir.resolve(path), NOFOLLOW_LINKS)) denied()
            }
            Files.walk(gitDir, 32).use { paths ->
                var count = 0
                for (path in paths) {
                    val attributes = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                    if (++count > 100_000 || attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile) ||
                        (attributes.isDirectory && gitDir.relativize(path).nameCount >= 32)) denied()
                }
            }
        } catch (_: IOException) { denied() } catch (_: java.io.UncheckedIOException) { denied() }
    }

    private fun ssh(user: String?, host: String, port: Int?, path: String, policy: GitRemotePolicy): GitRemoteLocation {
        if (user != null && (!USER.matches(user) || user.startsWith("-"))) refuse("VALIDATION_FAILED", "The SSH user name is invalid.")
        if (path.startsWith("-") || path.any { it == '\'' || it == '"' || it == '`' || it == '$' || it == ';' }) {
            refuse("VALIDATION_FAILED", "The SSH repository path has characters the workbench does not pass to SSH.")
        }
        allowed(host, policy)
        val url = "ssh://${user?.let { "$it@" } ?: ""}$host${port?.let { ":$it" } ?: ""}$path"
        return GitRemoteLocation(GitTransport.SSH, url, host, url)
    }

    private fun allowed(host: String, policy: GitRemotePolicy) {
        // A host that starts with '-' could be read as an SSH option (CVE-2017-1000117).
        if (!isHost(host)) refuse("VALIDATION_FAILED", "The remote host name is invalid.")
        if (host !in policy.allowedHosts) refuse("DESTINATION_NOT_ALLOWED", "The server operator has not allowed remotes on $host.")
    }
}

/** Builds the controlled transport for one location, and classifies its failures without echoing Git. */
object GitTransports {
    /** Single-quoted for the shell Git uses to run `core.sshCommand`; paths with quotes are refused. */
    private fun quoted(path: Path): String {
        val text = path.toString()
        require('\'' !in text && text.none { it.isISOControl() })
        return "'$text'"
    }

    fun context(location: GitRemoteLocation, policy: GitRemotePolicy, discoverFormat: Boolean = false): GitTransportContext {
        val protocol = when (location.transport) { GitTransport.HTTPS -> "https"; GitTransport.SSH -> "ssh"; GitTransport.ADMITTED -> "file" }
        val configuration = mutableListOf("protocol.$protocol.allow" to "always")
        val variables = mutableMapOf("GIT_ALLOW_PROTOCOL" to protocol)
        if (discoverFormat) {
            configuration += "protocol.version" to "2"
            // Packet capabilities expose object-format even for an empty remote. This is bounded
            // stderr only, never a trace file, client progress, HTTP header trace or persisted log.
            variables["GIT_TRACE_PACKET"] = "1"
        }
        val secrets = mutableMapOf<String, String>()
        when (location.transport) {
            GitTransport.ADMITTED -> {
                // Revalidate at each ls-remote/fetch, not only when the registration was created.
                val current = GitRemoteUrls.parse(location.display, policy)
                if (current.transport != GitTransport.ADMITTED || current.url != location.url) {
                    throw GitOperationRefusal("DESTINATION_NOT_ALLOWED", "The admitted remote changed since it was reviewed.")
                }
            }
            GitTransport.HTTPS -> {
                val host = checkNotNull(location.host)
                val credential = policy.credentials.https(host)
                configuration += listOf("http.sslVerify" to "true", "http.followRedirects" to "false",
                    "http.lowSpeedLimit" to "1", "http.lowSpeedTime" to "60")
                credential?.caFile?.let { configuration += "http.sslCAInfo" to it.toString() }
                if (credential != null) {
                    val password = try { GitStorage.read(credential.passwordFile, 4096).toString(Charsets.UTF_8).trimEnd('\n', '\r') }
                        catch (_: IOException) { throw GitOperationRefusal("CREDENTIAL_UNAVAILABLE", "The configured credential for $host could not be read on the server.") }
                    val basic = Base64.getEncoder().encodeToString("${credential.username}:$password".toByteArray())
                    // Scoped to this remote's origin through the environment only: never argv, never config files.
                    val origin = checkNotNull(Regex("^https://[^/]+").find(location.url)).value
                    secrets += mapOf("GIT_CONFIG_COUNT" to "1", "GIT_CONFIG_KEY_0" to "http.$origin/.extraHeader",
                        "GIT_CONFIG_VALUE_0" to "Authorization: Basic $basic")
                }
            }
            GitTransport.SSH -> {
                val host = checkNotNull(location.host)
                val credential = policy.credentials.ssh(host) ?: throw GitOperationRefusal("HOST_KEY_UNVERIFIED",
                    "No known host key is configured for $host, so its identity cannot be verified. Ask the operator to add it.")
                val command = buildString {
                    append("ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null")
                    append(" -o UserKnownHostsFile=").append(quoted(credential.knownHostsFile))
                    append(" -o IdentitiesOnly=yes -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4")
                    credential.identityFile?.let { append(" -i ").append(quoted(it)) }
                }
                configuration += "core.sshCommand" to command
                variables += "GIT_SSH_VARIANT" to "ssh"
            }
        }
        return GitTransportContext(configuration, variables, secrets)
    }

    /** A fixed public code and message for a failed transfer; Git's own output never reaches a client. */
    fun classify(failure: GitCommandException, diagnostic: String?, transport: GitTransport): Pair<String, String> {
        if (failure.kind == GitCommandException.Kind.STOPPED) return when (failure.stopReason) {
            "CANCELLED" -> "CANCELLED" to "The transfer was cancelled. Nothing was integrated; local work is unchanged."
            "DISK_LIMIT" -> "TRANSFER_LIMIT" to "The transfer exceeded the repository size bound and was stopped. Local work is unchanged."
            else -> "TRANSFER_STOPPED" to "The transfer was stopped. Local work is unchanged."
        }
        if (failure.kind == GitCommandException.Kind.TIMED_OUT) return "TRANSFER_TIMEOUT" to
            "The transfer did not finish within its time bound and was stopped. Local work is unchanged."
        if (failure.kind == GitCommandException.Kind.INTERRUPTED) return "INTERRUPTED" to "The transfer was interrupted."
        val text = (diagnostic ?: "").lowercase()
        return when {
            "host key verification failed" in text || "no ecdsa host key is known" in text || "host key for" in text ||
                "remote host identification has changed" in text -> "HOST_KEY_UNVERIFIED" to
                "The remote host key could not be verified against the server's known hosts. Nothing was transferred."
            "ssl certificate problem" in text || "certificate verification failed" in text || "unable to get local issuer" in text ||
                "self-signed certificate" in text || "self signed certificate" in text || "ssl:" in text && "certificate" in text ->
                "CERTIFICATE_INVALID" to "The remote's TLS certificate could not be verified. Nothing was transferred."
            "authentication failed" in text || "could not read username" in text || "could not read password" in text ||
                "terminal prompts disabled" in text || "permission denied (publickey" in text || "http 401" in text ||
                "returned error: 401" in text || "returned error: 403" in text -> "AUTHENTICATION_REQUIRED" to
                if (transport == GitTransport.ADMITTED) "The admitted remote refused access." else
                    "The remote requires credentials that are missing or were refused. Ask the operator to configure them; nothing was transferred."
            "could not resolve host" in text || "connection refused" in text || "network is unreachable" in text ||
                "connection timed out" in text || "operation timed out" in text || "failed to connect" in text ||
                "no route to host" in text -> "NETWORK_UNAVAILABLE" to "The remote could not be reached. Local work is unchanged; try again later."
            "repository not found" in text || "does not appear to be a git repository" in text || "returned error: 404" in text ||
                "not found" in text -> "REMOTE_NOT_FOUND" to "The remote repository was not found."
            "couldn't find remote ref" in text -> "REMOTE_REF_NOT_FOUND" to "The remote has no such branch."
            else -> "TRANSFER_FAILED" to "The transfer failed. Local work is unchanged."
        }
    }
}

/** A registered remote of one managed repository. Its URL is policy-checked and holds no secret. */
data class GitRemoteRecord(
    val remoteId: String,
    val repositoryId: String,
    val name: String,
    val location: GitRemoteLocation,
    val createdAt: Instant,
    val operationId: String,
) {
    val trackingPrefix: String get() = "refs/remotes/$name/"
}

/** Durable remote registrations and the repository's append-only audit history (#585, #601). */
internal object GitRemoteStore {
    const val REMOTES = "remotes"
    const val AUDIT = "audit.jsonl"
    const val MAX_REMOTES = 8
    const val MAX_AUDIT_BYTES = 4L * 1024 * 1024
    val NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

    /**
     * Each registration has its own identity: a remote removed and re-created under the same name
     * is a different remote, so a request reviewed against the old one cannot reach the new one.
     */
    fun remoteId(repositoryId: String, name: String, operationId: String) =
        "remote_" + GitStorage.sha256("git-remote-v2\n$repositoryId\n$name\n$operationId").take(32)

    /** A name that forms valid `refs/remotes/<name>/<branch>` refs (no `..`, `.lock`, leading dot or `HEAD`). */
    fun validName(name: String) = NAME.matches(name) && name != "HEAD" && GitRefNames.isPlausibleBranchName(name)

    fun write(directory: Path, record: GitRemoteRecord) {
        val remotes = GitStorage.directories(directory, REMOTES)
        GitStorage.replaceAtomically(remotes.resolve("${record.remoteId}.json"), buildJsonObject {
            put("schemaVersion", 1); put("remoteId", record.remoteId); put("repositoryId", record.repositoryId)
            put("name", record.name); put("transport", record.location.transport.wireName); put("url", record.location.url)
            put("host", record.location.host?.let(::JsonPrimitive) ?: JsonNull); put("display", record.location.display)
            put("createdAt", record.createdAt.toString()); put("operationId", record.operationId)
        }.toString().toByteArray())
    }

    fun list(directory: Path, repositoryId: String): List<GitRemoteRecord> {
        val remotes = directory.resolve(REMOTES)
        if (!Files.isDirectory(remotes, NOFOLLOW_LINKS)) return emptyList()
        return Files.newDirectoryStream(remotes).use { entries ->
            entries.filter { it.fileName.toString().matches(Regex("remote_[0-9a-f]{32}\\.json")) }.take(MAX_REMOTES + 1).mapNotNull { file ->
                try {
                    val value = Json.parseToJsonElement(GitStorage.read(file, 16 * 1024).toString(Charsets.UTF_8)).jsonObject
                    fun text(name: String) = value.getValue(name).jsonPrimitive.content
                    require(value.getValue("schemaVersion").jsonPrimitive.content == "1" && text("repositoryId") == repositoryId)
                    val name = text("name").also { require(NAME.matches(it)) }
                    require(text("remoteId") == remoteId(repositoryId, name, text("operationId")) && file.fileName.toString() == "${text("remoteId")}.json")
                    GitRemoteRecord(text("remoteId"), repositoryId, name, GitRemoteLocation(GitTransport.entries.single { it.wireName == text("transport") },
                        text("url"), value["host"]?.takeIf { it != JsonNull }?.jsonPrimitive?.content, text("display")),
                        Instant.parse(text("createdAt")), text("operationId"))
                } catch (_: Exception) {
                    throw ManagedGitException("STORAGE_FAILED", "A remote registration is unreadable. Preserve storage and inspect it.")
                }
            }.sortedBy { it.name }
        }
    }

    fun delete(directory: Path, remoteId: String) {
        if (Files.deleteIfExists(directory.resolve(REMOTES).resolve("$remoteId.json"))) GitStorage.forceDirectory(directory.resolve(REMOTES))
    }

    private const val PENDING_AUDIT = "remote-audit-pending"

    private fun pendingFile(directory: Path, operationId: String): Path {
        require(operationId.matches(Regex("operation_[0-9a-f]{32}")))
        return directory.resolve(PENDING_AUDIT).resolve("$operationId.json")
    }

    /** Durable write-ahead evidence retains the destination even after a registration is deleted. */
    fun prepareAudit(directory: Path, entry: JsonObject) {
        val operationId = entry.getValue("operationId").jsonPrimitive.content
        GitStorage.directories(directory, PENDING_AUDIT)
        GitStorage.forceDirectory(directory)
        GitStorage.replaceAtomically(pendingFile(directory, operationId), entry.toString().toByteArray())
    }

    fun hasPendingAudit(directory: Path, operationId: String): Boolean = Files.exists(pendingFile(directory, operationId), NOFOLLOW_LINKS)

    fun pendingAudit(directory: Path, operationId: String): JsonObject? {
        val file = pendingFile(directory, operationId)
        if (!Files.exists(file, NOFOLLOW_LINKS)) return null
        return Json.parseToJsonElement(GitStorage.read(file, 16 * 1024).toString(Charsets.UTF_8)).jsonObject.also {
            require(it.getValue("operationId").jsonPrimitive.content == operationId)
        }
    }

    /** Only discard the intent after its terminal operation record has been durably published. */
    fun clearPendingAudit(directory: Path, operationId: String) {
        if (Files.deleteIfExists(pendingFile(directory, operationId))) GitStorage.forceDirectory(directory.resolve(PENDING_AUDIT))
    }

    /** Idempotent completion, including a crash after audit publication but before operation completion. */
    @Synchronized
    fun auditOnce(directory: Path, entry: JsonObject) {
        val retained = auditLines(directory)
        val operationId = entry.getValue("operationId")
        val action = entry.getValue("action")
        val matches = retained.map { Json.parseToJsonElement(it).jsonObject }.filter {
            it["operationId"] == operationId && it["action"] == action
        }
        require(matches.size <= 1) { "Remote audit completion has duplicate retained evidence" }
        val existing = matches.singleOrNull()
        if (existing != null) {
            require(existing == entry) { "Remote audit completion conflicts with retained evidence" }
            return
        }
        writeAudit(directory, retained, entry)
    }

    /**
     * One audit entry: destination, refs, objects and outcome. It never holds a credential, and it
     * is separate from reconstruction evidence: nothing here accepts or rejects a revision.
     */
    @Synchronized
    fun audit(directory: Path, entry: JsonObject) = writeAudit(directory, auditLines(directory), entry)

    private fun auditLines(directory: Path): List<String> {
        val file = directory.resolve(AUDIT)
        if (!Files.exists(file, NOFOLLOW_LINKS)) return emptyList()
        return GitStorage.read(file, MAX_AUDIT_BYTES.toInt() + 64 * 1024).toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.toList()
    }

    private fun writeAudit(directory: Path, lines: List<String>, entry: JsonObject) {
        // Atomic replacement prevents a torn JSONL append from hiding the next recovered entry.
        var retained = lines
        var bytes = ((retained + entry.toString()).joinToString("\n") + "\n").toByteArray()
        while (bytes.size > MAX_AUDIT_BYTES && retained.isNotEmpty()) {
            retained = retained.drop((retained.size / 2).coerceAtLeast(1))
            bytes = ((retained + entry.toString()).joinToString("\n") + "\n").toByteArray()
        }
        require(bytes.size <= MAX_AUDIT_BYTES)
        GitStorage.replaceAtomically(directory.resolve(AUDIT), bytes)
    }

    fun auditEntries(directory: Path, limit: Int): List<JsonObject> {
        return auditLines(directory).asReversed().asSequence().mapNotNull { line ->
            try { Json.parseToJsonElement(line).jsonObject } catch (_: Exception) { null }
        }.take(limit).toList()
    }

    fun auditEntry(action: String, operationId: String, outcome: String, remote: GitRemoteRecord?, at: Instant,
        ref: String? = null, oldObjectId: String? = null, newObjectId: String? = null, detail: String? = null) = buildJsonObject {
        put("at", at.toString()); put("action", action); put("operationId", operationId); put("outcome", outcome)
        put("remoteId", remote?.remoteId?.let(::JsonPrimitive) ?: JsonNull)
        put("destination", remote?.location?.display?.let(::JsonPrimitive) ?: JsonNull)
        put("ref", ref?.let(::JsonPrimitive) ?: JsonNull)
        put("oldObjectId", oldObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("newObjectId", newObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("detail", detail?.let(::JsonPrimitive) ?: JsonNull)
    }

}

/** Throttled size check of a transfer's target directory; a bound overrun stops the process. */
internal class GitDiskWatch(private val directory: Path, private val maxBytes: Long, private val cancelled: () -> Boolean) {
    private var checkedAt = 0L
    fun stop(): String? {
        if (cancelled()) return "CANCELLED"
        val now = System.nanoTime()
        if (now - checkedAt < 500_000_000L) return null
        checkedAt = now
        return measure()
    }

    /** Unthrottled checks fail closed on unreadable storage at an admission boundary. */
    fun exceeded(): Boolean = bytes(directory) > maxBytes
    fun remaining(): Long = (maxBytes - bytes(directory)).coerceAtLeast(0)

    private fun measure(): String? = try {
        if (exceeded()) "DISK_LIMIT" else null
    } catch (_: IOException) { "DISK_LIMIT" } catch (_: java.io.UncheckedIOException) { "DISK_LIMIT" }

    companion object {
        fun bytes(directory: Path): Long = Files.walk(directory).use { paths ->
            var total = 0L
            for (path in paths) {
                if (Files.isRegularFile(path, NOFOLLOW_LINKS)) total = Math.addExact(total, Files.size(path))
            }
            total
        }
    }
}
