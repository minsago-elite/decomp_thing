package decompengine.git

/**
 * Shared, nonblocking admission boundary for workflows and file-replacing Git operations (#578).
 * Workflow admission holds a token until its active attempt/task is published; Git then checks that
 * durable activity while holding its exclusive token through checkout/removal and publication.
 * No callback runs under this monitor, avoiding job-service/Git-service lock-order inversions.
 */
class GitWorkspaceLeases {
    private val git = HashSet<String>()
    private val admissions = HashMap<String, Int>()

    @Synchronized
    fun tryGit(jobId: String): AutoCloseable? {
        if (jobId in git || admissions.getOrDefault(jobId, 0) != 0) return null
        git += jobId
        return token { git -= jobId }
    }

    @Synchronized
    fun tryWorkflowAdmission(jobId: String): AutoCloseable? {
        if (jobId in git) return null
        admissions[jobId] = admissions.getOrDefault(jobId, 0) + 1
        return token {
            val remaining = admissions.getValue(jobId) - 1
            if (remaining == 0) admissions.remove(jobId) else admissions[jobId] = remaining
        }
    }

    private fun token(release: () -> Unit): AutoCloseable = object : AutoCloseable {
        private var closed = false
        override fun close() = synchronized(this@GitWorkspaceLeases) {
            if (!closed) { closed = true; release() }
        }
    }
}
