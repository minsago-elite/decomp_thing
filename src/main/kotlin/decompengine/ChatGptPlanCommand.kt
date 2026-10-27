package decompengine

import decompengine.chatgpt.ChatGptPlanCredentialStore
import decompengine.chatgpt.ChatGptPlanOAuth
import decompengine.repair.ChatGptPlanRepairClient

internal fun runChatGptPlanCommand(args: List<String>) {
    val store = ChatGptPlanCredentialStore.default()
    val oauth = ChatGptPlanOAuth(store)
    try {
        when (args.firstOrNull()) {
            "login" -> {
                val options = args.drop(1)
                val accountId = optionValue(options, "--account")
                require(options.isEmpty() || options == listOf("--account", accountId)) {
                    "usage: llm_bin_patch chatgpt login [--account <id>]"
                }
                val account = oauth.signIn(accountId)
                println("Signed in to ChatGPT as ${account.email ?: "account ${account.id}"}.")
                println("Direct plan inference: ${if (account.canUseChatGptPlan) "enabled" else "not granted"}.")
                println("Choose a model with: llm_bin_patch chatgpt models --select <slug>")
            }
            "status" -> {
                require(args.size == 1) { "usage: llm_bin_patch chatgpt status" }
                val accounts = store.accounts()
                val activeId = store.activeAccount()?.id
                if (accounts.isEmpty()) println("No ChatGPT accounts are saved. Run llm_bin_patch chatgpt login.")
                accounts.forEach { account ->
                    val signedIn = account.refreshToken.isNotBlank()
                    println("${if (account.id == activeId) "*" else " "} ${account.id}: ${account.email ?: "unknown account"}; " +
                        "${if (signedIn) "signed in" else "signed out"}; direct plan inference=${account.canUseChatGptPlan}; model=${account.model ?: "unset"}")
                }
            }
            "models" -> {
                val client = ChatGptPlanRepairClient(store = store, oauth = oauth)
                val options = args.drop(1)
                val selected = optionValue(options, "--select")
                require(options.isEmpty() || options == listOf("--select", selected)) {
                    "usage: llm_bin_patch chatgpt models [--select <slug>]"
                }
                if (selected != null) client.selectModel(selected)
                val activeModel = store.activeAccount()?.model
                client.listModels().forEach { model ->
                    println("${if (model.slug == activeModel) "*" else " "} ${model.slug}\t${model.displayName}")
                }
                if (selected != null) println("Selected model: $selected")
            }
            "use" -> {
                val id = args.getOrNull(1)?.takeIf { !it.startsWith("-") }
                    ?: error("usage: llm_bin_patch chatgpt use <account-id>")
                require(args.size == 2) { "usage: llm_bin_patch chatgpt use <account-id>" }
                store.select(id)
                println("Active ChatGPT account: $id")
            }
            "logout" -> {
                val id = optionValue(args.drop(1), "--account")
                val options = args.drop(1)
                require(options.isEmpty() || options == listOf("--account", id)) { "usage: llm_bin_patch chatgpt logout [--account <id>]" }
                val confirmed = oauth.signOut(id)
                println("Local ChatGPT credentials cleared${if (confirmed) " and refresh token revocation confirmed." else "; server revocation was not confirmed."}")
            }
            else -> chatGptUsageError("expected login, status, models, use, or logout")
        }
    } catch (failure: IllegalArgumentException) {
        chatGptUsageError(failure.message ?: "invalid ChatGPT command")
    } catch (failure: Exception) {
        System.err.println(failure.message ?: "ChatGPT operation failed")
        kotlin.system.exitProcess(1)
    }
}

private fun optionValue(args: List<String>, name: String): String? {
    val index = args.indexOf(name)
    if (index < 0) return null
    require(index + 1 < args.size && args[index + 1].isNotBlank()) { "$name requires a value" }
    require(args.count { it == name } == 1) { "$name may be specified only once" }
    return args[index + 1]
}

private fun chatGptUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch chatgpt login [--account <id>] | status | models [--select <slug>] | use <account-id> | logout [--account <id>]")
    kotlin.system.exitProcess(2)
}
