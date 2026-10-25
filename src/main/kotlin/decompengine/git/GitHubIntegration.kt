package decompengine.git

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration

/** One managed remote bound to one hosting repository (#602). */
data class GitHubBinding(val remote: String, val owner: String, val repository: String) {
    init {
        require(owner.matches(NAME) && repository.matches(NAME)) { "A GitHub owner or repository name is invalid." }
    }
    val path: String get() = "/repos/$owner/$repository"
    companion object { private val NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,99}") }
}

/**
 * Optional hosting integration, off unless the operator configures it. The token stays in its
 * file and is read per request; without one the integration is read-only.
 *
 * ```json
 * {"apiUrl": "https://api.github.com", "tokenFile": "/etc/decomp/github-token",
 *  "repositories": [{"remote": "https://github.com/team/project.git", "repository": "team/project"}]}
 * ```
 */
data class GitHubConfiguration(val apiUrl: URI, val tokenFile: Path?, val bindings: List<GitHubBinding>) {
    init {
        require(apiUrl.scheme == "https" || (apiUrl.scheme == "http" && apiUrl.host in setOf("127.0.0.1", "localhost"))) {
            "The GitHub API URL must use HTTPS (plain HTTP only for a loopback test provider)."
        }
        require(apiUrl.rawQuery == null && apiUrl.rawFragment == null && apiUrl.rawUserInfo == null)
        require(bindings.size <= 32 && bindings.map { it.remote }.toSet().size == bindings.size)
    }
    val writable: Boolean get() = tokenFile != null
    fun binding(remote: GitRemoteRecord): GitHubBinding? = bindings.singleOrNull { it.remote == remote.location.display }
    override fun toString() = "GitHubConfiguration($apiUrl, writable=$writable, ${bindings.size} repositories)"

    companion object {
        fun load(file: Path): GitHubConfiguration {
            val value = try { Json.parseToJsonElement(GitStorage.read(file, 64 * 1024).toString(Charsets.UTF_8)).jsonObject }
                catch (_: Exception) { throw IllegalArgumentException("The GitHub configuration is unreadable or not JSON.") }
            require(value.keys.all { it in setOf("apiUrl", "tokenFile", "repositories") }) { "The GitHub configuration has unknown fields." }
            val token = value["tokenFile"]?.takeIf { it != JsonNull }?.jsonPrimitive?.content?.let(Path::of)
            require(token == null || (token.isAbsolute && Files.isRegularFile(token))) { "The GitHub token file must be an existing absolute file." }
            return GitHubConfiguration(URI(value.getValue("apiUrl").jsonPrimitive.content.removeSuffix("/")), token,
                value["repositories"]?.jsonArray.orEmpty().map { item ->
                    val entry = item.jsonObject
                    val (owner, repository) = entry.getValue("repository").jsonPrimitive.content.split('/').takeIf { it.size == 2 }
                        ?: throw IllegalArgumentException("A GitHub repository is named owner/repository.")
                    GitHubBinding(entry.getValue("remote").jsonPrimitive.content, owner, repository)
                })
        }
    }
}

/** A pull request as the provider reports it; nothing here implies build or reconstruction acceptance. */
data class GitHubPull(val number: Int, val state: String, val title: String, val url: String, val headRef: String, val baseRef: String,
    val headSha: String?)

class GitHubException(val code: String, message: String, val retryAfterSeconds: Long? = null) : Exception(message)

/** Bounded, redirect-free provider client. Requests and errors never carry the token. */
class GitHubClient(private val configuration: GitHubConfiguration,
    private val http: HttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build(),
    /** Overall bound for receiving one response body after its headers. */
    private val bodyTimeout: Duration = Duration.ofSeconds(20)) {

    private fun token(): String? = configuration.tokenFile?.let { file ->
        try { GitStorage.read(file, 4096).toString(Charsets.UTF_8).trim() } catch (_: IOException) {
            throw GitHubException("GITHUB_CREDENTIAL_UNAVAILABLE", "The configured GitHub token could not be read on the server.")
        }
    }

    private fun send(method: String, path: String, body: JsonObject? = null, write: Boolean = false): Pair<Int, kotlinx.serialization.json.JsonElement?> {
        val builder = HttpRequest.newBuilder(URI("${configuration.apiUrl}$path")).timeout(Duration.ofSeconds(20))
            .header("Accept", "application/vnd.github+json").header("X-GitHub-Api-Version", "2022-11-28")
        val token = token()
        if (write && token == null) throw GitHubException("GITHUB_READ_ONLY", "The GitHub integration is read-only: no token is configured on the server.")
        token?.let { builder.header("Authorization", "Bearer $it") }
        if (body != null) builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body.toString()))
        else builder.method(method, HttpRequest.BodyPublishers.noBody())
        val response = try { http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream()) } catch (failure: IOException) {
            throw GitHubException("GITHUB_UNREACHABLE", "GitHub could not be reached. Local Git work is unaffected; try again later.")
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt(); throw GitHubException("GITHUB_UNREACHABLE", "The GitHub request was interrupted.")
        }
        // The request timeout covers only the headers; the body is read under the same overall deadline.
        val stream = response.body()
        val reading = java.util.concurrent.CompletableFuture.supplyAsync { stream.use { it.readNBytes(1024 * 1024 + 1) } }
        val bytes = try { reading.get(bodyTimeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: java.util.concurrent.TimeoutException) {
            try { stream.close() } catch (_: IOException) { }
            reading.cancel(true)
            throw GitHubException("GITHUB_UNREACHABLE", "GitHub stopped sending its response. Local Git work is unaffected; try again later.")
        } catch (_: java.util.concurrent.ExecutionException) {
            throw GitHubException("GITHUB_UNREACHABLE", "GitHub's response could not be read. Local Git work is unaffected; try again later.")
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt(); reading.cancel(true); throw GitHubException("GITHUB_UNREACHABLE", "The GitHub request was interrupted.")
        }
        if (bytes.size > 1024 * 1024) throw GitHubException("GITHUB_RESPONSE_INVALID", "GitHub returned an oversized response.")
        val parsed = try { if (bytes.isEmpty()) null else Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)) } catch (_: Exception) {
            throw GitHubException("GITHUB_RESPONSE_INVALID", "GitHub returned a response the workbench cannot read.")
        }
        val status = response.statusCode()
        val retry = response.headers().firstValue("Retry-After").orElse(null)?.toLongOrNull()
        val exhausted = response.headers().firstValue("X-RateLimit-Remaining").orElse(null) == "0"
        when {
            status == 401 -> throw GitHubException("GITHUB_UNAUTHORIZED", "GitHub refused the server's credential. Ask the operator to renew it.")
            status == 429 || (status == 403 && (exhausted || retry != null)) -> throw GitHubException("GITHUB_RATE_LIMITED",
                "GitHub's rate limit is exhausted. Try again later.", retry)
            status == 403 -> throw GitHubException("GITHUB_FORBIDDEN", "The server's GitHub credential lacks permission for this repository.")
            status == 404 -> throw GitHubException("GITHUB_NOT_FOUND", "GitHub has no such repository or branch, or the credential cannot see it.")
        }
        return status to parsed
    }

    private fun pull(value: kotlinx.serialization.json.JsonElement): GitHubPull = try { parsePull(value) } catch (failure: GitHubException) {
        throw failure
    } catch (_: RuntimeException) {
        // A missing or mistyped field is an unreadable answer, never an internal failure.
        throw GitHubException("GITHUB_RESPONSE_INVALID", "GitHub returned a pull request the workbench cannot read.")
    }

    private fun parsePull(value: kotlinx.serialization.json.JsonElement): GitHubPull {
        val item = value.jsonObject
        fun text(name: String) = item.getValue(name).jsonPrimitive.content
        val head = item.getValue("head").jsonObject
        val url = text("html_url").takeIf { it.startsWith("https://") && it.length <= 2048 } ?: throw GitHubException("GITHUB_RESPONSE_INVALID",
            "GitHub returned an unexpected pull request link.")
        return GitHubPull(item.getValue("number").jsonPrimitive.intOrNull ?: throw GitHubException("GITHUB_RESPONSE_INVALID", "Invalid pull request."),
            text("state"), text("title").take(256), url, head.getValue("ref").jsonPrimitive.content,
            item.getValue("base").jsonObject.getValue("ref").jsonPrimitive.content,
            head["sha"]?.jsonPrimitive?.contentOrNull?.takeIf { it.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}")) })
    }

    /** Whether a creation failure is a definite refusal; anything else may have created the pull request. */
    fun definiteRefusal(code: String) = code in setOf("GITHUB_UNAUTHORIZED", "GITHUB_FORBIDDEN", "GITHUB_NOT_FOUND",
        "GITHUB_VALIDATION_FAILED", "GITHUB_READ_ONLY", "GITHUB_CREDENTIAL_UNAVAILABLE", "GITHUB_RATE_LIMITED")

    /** Pull requests whose head is [head] in the bound repository (same-repository heads only). */
    fun pulls(binding: GitHubBinding, head: String, base: String? = null): List<GitHubPull> {
        fun encode(value: String) = URLEncoder.encode(value, Charsets.UTF_8)
        val query = "state=all&head=${encode("${binding.owner}:$head")}" + (base?.let { "&base=${encode(it)}" } ?: "")
        val (status, body) = send("GET", "${binding.path}/pulls?$query")
        if (status != 200 || body !is JsonArray) throw GitHubException("GITHUB_RESPONSE_INVALID", "GitHub returned an unexpected pull request listing.")
        return body.take(30).map(::pull).filter { it.headRef == head }
    }

    /** Create one pull request. A duplicate is reported as `GITHUB_PR_EXISTS` so the caller reconciles it. */
    fun create(binding: GitHubBinding, head: String, base: String, title: String, body: String): GitHubPull {
        val (status, response) = send("POST", "${binding.path}/pulls", buildJsonObject {
            put("head", head); put("base", base); put("title", title); put("body", body)
        }, write = true)
        if (status == 422) {
            val exists = ((response as? JsonObject)?.get("errors") as? JsonArray)
                ?.any { ((it as? JsonObject)?.get("code") as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull == "already_exists" } == true
            throw GitHubException(if (exists) "GITHUB_PR_EXISTS" else "GITHUB_VALIDATION_FAILED",
                if (exists) "A pull request for this head and base already exists." else "GitHub rejected the pull request; check that both branches exist.")
        }
        if (status != 201 || response == null) throw GitHubException("GITHUB_RESPONSE_INVALID", "GitHub returned an unexpected pull request response.")
        return pull(response)
    }
}
