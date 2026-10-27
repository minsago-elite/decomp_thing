package decompengine.chatgpt

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.time.Instant
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock

/** One local ChatGPT registration. Token values are deliberately absent from [toString]. */
class ChatGptPlanAccount internal constructor(
    val id: String,
    val email: String?,
    val clientId: String,
    val subject: String,
    val model: String?,
    val scopes: Set<String>,
    val expiresAt: Instant,
    internal val idToken: String,
    internal val accessToken: String,
    internal val refreshToken: String,
) {
    val canUseChatGptPlan: Boolean
        get() = REQUIRED_PLAN_SCOPES.all(scopes::contains)

    override fun toString(): String =
        "ChatGptPlanAccount(id=$id, email=${email ?: "unknown"}, clientId=$clientId, model=${model ?: "unset"}, " +
            "canUseChatGptPlan=$canUseChatGptPlan, tokens=[redacted])"
}

/**
 * Private local credential store for the SIWC open-source flow.
 *
 * The file is kept outside project state, written atomically with owner-only permissions, and
 * protected by an OS file lock so rotating refresh tokens cannot race across CLI processes.
 */
class ChatGptPlanCredentialStore private constructor(private val directory: Path) {
    private val file = directory.resolve(STORE_FILE_NAME)
    private val lockFile = directory.resolve(LOCK_FILE_NAME)

    fun hostId(): String = withExclusiveLock {
        val current = readStore()
        current.hostId ?: UUID.randomUUID().let { "urn:uuid:$it" }.also { host ->
            writeStore(current.copy(hostId = host))
        }
    }

    fun accounts(): List<ChatGptPlanAccount> = withExclusiveLock {
        val current = readStore()
        current.profiles.map(StoredProfile::toAccount)
    }

    fun activeAccount(): ChatGptPlanAccount? = withExclusiveLock {
        val current = readStore()
        current.profiles.firstOrNull { it.id == current.activeProfileId }?.toAccount()
    }

    fun account(profileId: String): ChatGptPlanAccount? = withExclusiveLock {
        readStore().profiles.firstOrNull { it.id == profileId }?.toAccount()
    }

    fun saveNewAccount(account: NewChatGptPlanAccount, activate: Boolean = true): ChatGptPlanAccount =
        withExclusiveLock {
            val store = readStore()
            require(store.profiles.none { it.clientId == account.clientId }) {
                "this ChatGPT registration is already saved"
            }
            val profile = StoredProfile(
                id = UUID.randomUUID().toString(),
                email = account.email,
                clientId = account.clientId,
                subject = account.subject,
                idToken = account.idToken,
                accessToken = account.accessToken,
                refreshToken = account.refreshToken,
                expiresAtEpochSeconds = account.expiresAt.epochSecond,
                scopes = account.scopes.sorted(),
                model = null,
            )
            writeStore(
                store.copy(
                    profiles = store.profiles + profile,
                    activeProfileId = if (activate) profile.id else store.activeProfileId,
                ),
            )
            profile.toAccount()
        }

    fun replaceAccount(profileId: String, account: NewChatGptPlanAccount): ChatGptPlanAccount = withExclusiveLock {
        val store = readStore()
        val index = store.profiles.indexOfFirst { it.id == profileId }
        if (index < 0) throw ChatGptPlanAuthenticationException("The selected ChatGPT account is no longer saved.")
        val previous = store.profiles[index]
        require(previous.clientId == account.clientId && previous.subject == account.subject) {
            "reauthorization returned a different ChatGPT account identity"
        }
        val replacement = previous.copy(
            email = account.email,
            idToken = account.idToken,
            accessToken = account.accessToken,
            refreshToken = account.refreshToken,
            expiresAtEpochSeconds = account.expiresAt.epochSecond,
            scopes = account.scopes.sorted(),
        )
        val profiles = store.profiles.toMutableList().also { it[index] = replacement }
        writeStore(store.copy(profiles = profiles, activeProfileId = profileId))
        replacement.toAccount()
    }

    /** Refreshes under the cross-process store lock and atomically saves a rotated refresh token. */
    fun withFreshAccessToken(
        profileId: String?,
        refreshBefore: Instant = Instant.now().plusSeconds(60),
        refresh: (clientId: String, refreshToken: String) -> RefreshedChatGptPlanTokens,
        use: (ChatGptPlanAccount) -> Unit,
    ) {
        val account = withExclusiveLock {
            val store = readStore()
            val selectedId = profileId ?: store.activeProfileId
                ?: throw ChatGptPlanAuthenticationException("Sign in with ChatGPT first: run llm_bin_patch chatgpt login.")
            val profileIndex = store.profiles.indexOfFirst { it.id == selectedId }
            if (profileIndex < 0) throw ChatGptPlanAuthenticationException("The selected ChatGPT account is no longer saved.")
            var profile = store.profiles[profileIndex]
            if (profile.expiresAtEpochSeconds <= refreshBefore.epochSecond) {
                val rotated = refresh(profile.clientId, profile.refreshToken)
                profile = profile.copy(
                    accessToken = rotated.accessToken,
                    refreshToken = rotated.refreshToken,
                    idToken = rotated.idToken ?: profile.idToken,
                    expiresAtEpochSeconds = rotated.expiresAt.epochSecond,
                    scopes = rotated.scopes?.sorted() ?: profile.scopes,
                )
                val profiles = store.profiles.toMutableList().also { it[profileIndex] = profile }
                writeStore(store.copy(profiles = profiles))
            }
            profile.toAccount()
        }
        use(account)
    }

    fun select(profileId: String) = withExclusiveLock {
        val store = readStore()
        require(store.profiles.any { it.id == profileId }) { "unknown ChatGPT account id" }
        writeStore(store.copy(activeProfileId = profileId))
    }

    fun setModel(profileId: String?, model: String) = withExclusiveLock {
        require(model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}"))) { "invalid ChatGPT model slug" }
        val store = readStore()
        val selectedId = profileId ?: store.activeProfileId
            ?: throw ChatGptPlanAuthenticationException("Sign in with ChatGPT first: run llm_bin_patch chatgpt login.")
        val index = store.profiles.indexOfFirst { it.id == selectedId }
        if (index < 0) throw ChatGptPlanAuthenticationException("The selected ChatGPT account is no longer saved.")
        val profiles = store.profiles.toMutableList().also { it[index] = it[index].copy(model = model) }
        writeStore(store.copy(profiles = profiles))
    }

    /** Removes the selected local credential material, retaining its issued client/account mapping. */
    fun clearTokens(profileId: String?) = withExclusiveLock {
        val store = readStore()
        val selectedId = profileId ?: store.activeProfileId
            ?: throw ChatGptPlanAuthenticationException("No active ChatGPT account is selected.")
        val index = store.profiles.indexOfFirst { it.id == selectedId }
        if (index < 0) throw ChatGptPlanAuthenticationException("The selected ChatGPT account is no longer saved.")
        val profile = store.profiles[index]
        val profiles = store.profiles.toMutableList().also {
            it[index] = profile.copy(idToken = "", accessToken = "", refreshToken = "", expiresAtEpochSeconds = 0)
        }
        writeStore(store.copy(profiles = profiles))
    }

    private fun readStore(): StoreDocument {
        ensureSecureDirectory()
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return StoreDocument()
        verifyPrivateRegularFile(file)
        return try {
            val root = Json.parseToJsonElement(Files.readString(file)).jsonObject
            require(root.keys == setOf("schemaVersion", "hostId", "activeProfileId", "profiles")) {
                "credential store has an unexpected shape"
            }
            require(root.getValue("schemaVersion").jsonPrimitive.content.toInt() == STORE_SCHEMA_VERSION) {
                "unsupported ChatGPT credential store version"
            }
            val hostId = root.optionalString("hostId")
            require(hostId == null || hostId.matches(HOST_ID_PATTERN)) { "credential store host id is invalid" }
            val profiles = root.getValue("profiles").jsonArray.map(::readProfile)
            require(profiles.map(StoredProfile::id).distinct().size == profiles.size) { "credential store profile ids are duplicated" }
            require(profiles.map(StoredProfile::clientId).distinct().size == profiles.size) { "credential store client ids are duplicated" }
            val active = root.optionalString("activeProfileId")
            require(active == null || profiles.any { it.id == active }) { "credential store active account is missing" }
            StoreDocument(hostId, active, profiles)
        } catch (failure: Exception) {
            if (failure is ChatGptPlanAuthenticationException) throw failure
            throw ChatGptPlanAuthenticationException("The local ChatGPT credential store is invalid or unreadable.", failure)
        }
    }

    private fun readProfile(value: kotlinx.serialization.json.JsonElement): StoredProfile {
        val root = value.jsonObject
        require(root.keys == setOf(
            "id", "email", "clientId", "subject", "idToken", "accessToken", "refreshToken",
            "expiresAtEpochSeconds", "scopes", "model",
        )) { "credential profile has an unexpected shape" }
        val profile = StoredProfile(
            id = root.getValue("id").jsonPrimitive.content,
            email = root.optionalString("email"),
            clientId = root.getValue("clientId").jsonPrimitive.content,
            subject = root.getValue("subject").jsonPrimitive.content,
            idToken = root.getValue("idToken").jsonPrimitive.content,
            accessToken = root.getValue("accessToken").jsonPrimitive.content,
            refreshToken = root.getValue("refreshToken").jsonPrimitive.content,
            expiresAtEpochSeconds = root.getValue("expiresAtEpochSeconds").jsonPrimitive.content.toLong(),
            scopes = root.getValue("scopes").jsonArray.map { it.jsonPrimitive.content },
            model = root.optionalString("model"),
        )
        require(profile.id.matches(PROFILE_ID_PATTERN)) { "credential profile id is invalid" }
        require(profile.clientId.matches(CLIENT_ID_PATTERN)) { "credential profile client id is invalid" }
        require(profile.subject.isNotBlank() && profile.subject.length <= 2048) { "credential profile subject is invalid" }
        require(profile.scopes.distinct().size == profile.scopes.size) { "credential profile scopes are duplicated" }
        require(profile.model == null || profile.model.matches(MODEL_ID_PATTERN)) { "credential profile model is invalid" }
        val emptyTokens = profile.idToken.isEmpty() && profile.accessToken.isEmpty() && profile.refreshToken.isEmpty()
        require(emptyTokens || listOf(profile.idToken, profile.accessToken, profile.refreshToken).all { it.isNotBlank() }) {
            "credential profile token set is incomplete"
        }
        return profile
    }

    private fun writeStore(document: StoreDocument) {
        ensureSecureDirectory()
        val encoded = encodeStore(document).toByteArray(Charsets.UTF_8)
        val temp = Files.createTempFile(directory, ".chatgpt-plan-", ".tmp", *privateFileAttributes())
        try {
            FileChannel.open(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { channel ->
                var buffer = java.nio.ByteBuffer.wrap(encoded)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            verifyPrivateRegularFile(temp)
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING)
            }
            verifyPrivateRegularFile(file)
            runCatching { FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) } }
        } finally {
            Files.deleteIfExists(temp)
        }
    }

    private fun encodeStore(document: StoreDocument): String = Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            put("schemaVersion", JsonPrimitive(STORE_SCHEMA_VERSION))
            put("hostId", document.hostId?.let(::JsonPrimitive) ?: JsonNull)
            put("activeProfileId", document.activeProfileId?.let(::JsonPrimitive) ?: JsonNull)
            put("profiles", buildJsonArray { document.profiles.forEach { profile -> add(encodeProfile(profile)) } })
        },
    )

    private fun encodeProfile(profile: StoredProfile): JsonObject = buildJsonObject {
        put("id", JsonPrimitive(profile.id))
        put("email", profile.email?.let(::JsonPrimitive) ?: JsonNull)
        put("clientId", JsonPrimitive(profile.clientId))
        put("subject", JsonPrimitive(profile.subject))
        put("idToken", JsonPrimitive(profile.idToken))
        put("accessToken", JsonPrimitive(profile.accessToken))
        put("refreshToken", JsonPrimitive(profile.refreshToken))
        put("expiresAtEpochSeconds", JsonPrimitive(profile.expiresAtEpochSeconds))
        put("scopes", JsonArray(profile.scopes.map(::JsonPrimitive)))
        put("model", profile.model?.let(::JsonPrimitive) ?: JsonNull)
    }

    private fun ensureSecureDirectory() {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            val parent = requireNotNull(directory.parent) { "ChatGPT credential directory requires a parent" }
            Files.createDirectories(parent)
            try {
                Files.createDirectory(directory, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS))
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                // Verify a concurrently created directory below before using it.
            }
        }
        require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(directory)) {
            "ChatGPT credential directory must be a real directory"
        }
        val mode = Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS)
        require(mode.none { it in GROUP_OR_OTHER_PERMISSIONS }) {
            "ChatGPT credential directory permissions must be owner-only"
        }
        requireSameOwner(directory)
    }

    private fun verifyPrivateRegularFile(path: Path) {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "ChatGPT credential file must be a regular file without links"
        }
        val mode = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
        require(mode.none { it in GROUP_OR_OTHER_PERMISSIONS }) {
            "ChatGPT credential file permissions must be owner-only"
        }
        requireSameOwner(path)
        runCatching { Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number }
            .getOrNull()?.let { require(it.toInt() == 1) { "ChatGPT credential file must have one link" } }
    }

    private fun requireSameOwner(path: Path) {
        val home = Path.of(System.getProperty("user.home")).toAbsolutePath().normalize()
        val expected = Files.getOwner(home, LinkOption.NOFOLLOW_LINKS)
        require(Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) == expected) {
            "ChatGPT credential storage must be owned by the current user"
        }
    }

    private fun <T> withExclusiveLock(block: () -> T): T {
        ensureSecureDirectory()
        val processLock = PROCESS_LOCK
        processLock.lock()
        return try {
            if (Files.exists(lockFile, LinkOption.NOFOLLOW_LINKS)) verifyPrivateRegularFile(lockFile)
            FileChannel.open(
                lockFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                runCatching { Files.setPosixFilePermissions(lockFile, PRIVATE_FILE_PERMISSIONS) }
                verifyPrivateRegularFile(lockFile)
                channel.lock().use { _: FileLock -> block() }
            }
        } finally {
            processLock.unlock()
        }
    }

    private fun JsonObject.optionalString(name: String): String? = when (val value = getValue(name)) {
        JsonNull -> null
        else -> value.jsonPrimitive.content
    }

    private data class StoreDocument(
        val hostId: String? = null,
        val activeProfileId: String? = null,
        val profiles: List<StoredProfile> = emptyList(),
    )

    private data class StoredProfile(
        val id: String,
        val email: String?,
        val clientId: String,
        val subject: String,
        val idToken: String,
        val accessToken: String,
        val refreshToken: String,
        val expiresAtEpochSeconds: Long,
        val scopes: List<String>,
        val model: String?,
    ) {
        fun toAccount() = ChatGptPlanAccount(
            id, email, clientId, subject, model, scopes.toSet(), Instant.ofEpochSecond(expiresAtEpochSeconds),
            idToken, accessToken, refreshToken,
        )
    }

    companion object {
        private const val STORE_SCHEMA_VERSION = 1
        private const val STORE_FILE_NAME = "chatgpt-plan-credentials.json"
        private const val LOCK_FILE_NAME = "chatgpt-plan-credentials.lock"
        private val PROFILE_ID_PATTERN = Regex("[0-9a-fA-F-]{36}")
        private val CLIENT_ID_PATTERN = Regex("[A-Za-z0-9_.-]{1,256}")
        private val MODEL_ID_PATTERN = Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
        private val HOST_ID_PATTERN = Regex("urn:uuid:[0-9a-fA-F-]{36}")
        private val GROUP_OR_OTHER_PERMISSIONS = setOf(
            PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE,
        )
        private val PRIVATE_DIRECTORY_PERMISSIONS = setOf(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
        )
        private val PRIVATE_FILE_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        private val PROCESS_LOCK = ReentrantLock()

        fun default(): ChatGptPlanCredentialStore {
            val override = System.getenv()["DECOMP_CHATGPT_TOKEN_STORE"]?.takeIf(String::isNotBlank)
            val directory = override?.let(Path::of) ?: Path.of(
                System.getProperty("user.home"), ".config", "decomp_engine",
            )
            require(directory.isAbsolute) { "DECOMP_CHATGPT_TOKEN_STORE must be an absolute path" }
            return ChatGptPlanCredentialStore(directory.normalize())
        }

        internal fun create(directory: Path): ChatGptPlanCredentialStore =
            ChatGptPlanCredentialStore(directory.toAbsolutePath().normalize())

        private fun privateFileAttributes(): Array<java.nio.file.attribute.FileAttribute<Set<PosixFilePermission>>> =
            arrayOf(java.nio.file.attribute.PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS))
    }
}

private val REQUIRED_PLAN_SCOPES = setOf("offline_access", "resource.invoke", "chatgpt.tokens.use.direct")

data class NewChatGptPlanAccount(
    val email: String?,
    val clientId: String,
    val subject: String,
    val idToken: String,
    val accessToken: String,
    val refreshToken: String,
    val expiresAt: Instant,
    val scopes: Set<String>,
)

data class RefreshedChatGptPlanTokens(
    val accessToken: String,
    val refreshToken: String,
    val expiresAt: Instant,
    val scopes: Set<String>? = null,
    val idToken: String? = null,
)

class ChatGptPlanAuthenticationException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
