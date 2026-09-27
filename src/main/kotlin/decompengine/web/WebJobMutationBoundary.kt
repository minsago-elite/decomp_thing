package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.PublishedJobUpload
import decompengine.jobs.WorkflowPinActor
import decompengine.jobs.WorkflowPinRequestResult
import java.io.InputStream

/**
 * Mints a request-scoped capability only after the shared local mutation policy succeeds.
 * HTTP adapters keep their transport parsing and response shapes, but cannot reach a persisted
 * job mutation through this boundary without the same session, Origin, content-type and CSRF
 * checks. The service remains the sole owner of storage admission and lifecycle transitions.
 */
internal class WebJobMutationBoundary(
    private val access: LocalWebAccess,
    private val jobs: WebJobService,
) {
    fun authorizeUpload(exchange: HttpExchange): AuthorizedWebJobUpload {
        val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.multipartUpload()))
        return AuthorizedWebJobUpload(session, jobs)
    }

    fun authorizeLegacyStart(exchange: HttpExchange): AuthorizedLegacyWebJobStart {
        checkNotNull(access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST")))
        return AuthorizedLegacyWebJobStart(jobs)
    }

    fun authorizeProgressPin(exchange: HttpExchange): AuthorizedWebProgressPin {
        val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.jsonMutation("PUT")))
        return AuthorizedWebProgressPin(session, jobs)
    }
}

/** Upload-only capability shared by the legacy and versioned HTTP adapters. */
internal class AuthorizedWebJobUpload internal constructor(
    private val session: AuthorizedWebSession,
    private val jobs: WebJobService,
) {
    val sessionId: String get() = session.sessionId

    fun uploadMultipartReceipt(
        input: InputStream,
        contentType: String,
        idempotencyKey: String? = null,
        progress: WebUploadProgress.Transfer? = null,
    ): PublishedJobUpload = jobs.uploadMultipartReceipt(input, contentType, idempotencyKey, progress)
}

/** Legacy workflow-start capability; the versioned start operation remains intentionally absent. */
internal class AuthorizedLegacyWebJobStart internal constructor(
    private val jobs: WebJobService,
) {
    fun start(jobId: String, workflow: WebWorkflow): WebWorkflowAdmission = jobs.start(jobId, workflow)
}

/** Progress-retention capability whose actor identity can only come from authorization. */
internal class AuthorizedWebProgressPin internal constructor(
    private val session: AuthorizedWebSession,
    private val jobs: WebJobService,
) {
    fun request(
        jobId: String,
        runId: String,
        expectedRunVersion: String,
        pinned: Boolean,
        requestKey: String,
    ): WorkflowPinRequestResult = jobs.requestProgressRetentionPinned(
        jobId,
        runId,
        expectedRunVersion,
        pinned,
        WorkflowPinActor.browserSession(session.sessionId),
        requestKey,
    )
}
