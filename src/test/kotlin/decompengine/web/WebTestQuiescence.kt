package decompengine.web

import java.time.Duration

/*
 * Audited responses are followed by an fsync'd audit append on the request thread (#521). Until the server drains
 * those appends itself (#2029), tests that stop the server or snapshot stored bytes after an audited request first
 * wait here for admitted handlers to finish. Removing these helpers is the intended follow-up.
 */

/** Waits until no admitted HTTP handler, including a post-response audit append, is running. */
internal fun UploadServer.awaitRequestsIdle(timeout: Duration = Duration.ofSeconds(10)) {
    check(waitForRequestsIdle(timeout)) {
        "HTTP handlers, including post-response audit appends, did not finish within ${timeout.toSeconds()} s " +
            "(${activeRequestCount()} still active)"
    }
}

/**
 * Lets admitted handlers finish before [UploadServer.stop]'s bounded request drain. The wait does not throw, so a
 * test failure is not masked from a `finally` block; a handler that is still running fails the stop itself.
 */
internal fun UploadServer.stopWhenIdle(timeout: Duration = Duration.ofSeconds(10)) {
    waitForRequestsIdle(timeout)
    stop()
}

private fun UploadServer.waitForRequestsIdle(timeout: Duration): Boolean {
    val deadline = System.nanoTime() + timeout.toNanos()
    while (activeRequestCount() != 0) {
        if (System.nanoTime() >= deadline) return false
        Thread.sleep(5)
    }
    return true
}
