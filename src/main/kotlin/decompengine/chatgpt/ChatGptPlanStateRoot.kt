package decompengine.chatgpt

import java.nio.file.Path

/** Runtime credential root. Tests should pass a path below the repository build directory. */
object ChatGptPlanStateRoot {
    fun resolve(environment: Map<String, String> = System.getenv(), userHome: String = System.getProperty("user.home")): Path {
        val configured = environment["DECOMP_CHATGPT_TOKEN_STORE"]
            ?: environment["XDG_STATE_HOME"]?.let { "$it/decomp_engine/chatgpt-plan" }
            ?: "$userHome/.local/state/decomp_engine/chatgpt-plan"
        val path = try { Path.of(configured) } catch (_: Exception) {
            throw IllegalArgumentException("invalid ChatGPT token store path")
        }
        require(path.isAbsolute) { "ChatGPT token store path must be absolute" }
        return path.normalize()
    }
}
