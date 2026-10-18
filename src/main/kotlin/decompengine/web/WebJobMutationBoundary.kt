package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.PublishedJobUpload
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowPinActor
import decompengine.jobs.WorkflowPinRequestResult
import decompengine.jobs.WorkflowCancellationActor
import decompengine.jobs.WorkflowCancellationRequestResult
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

    fun authorizeDurableStart(exchange: HttpExchange): AuthorizedWebWorkflowStart {
        checkNotNull(access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST")))
        return AuthorizedWebWorkflowStart(jobs)
    }

    fun authorizeCancellation(exchange: HttpExchange): AuthorizedWebCancellation {
        val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST")))
        return AuthorizedWebCancellation(session, jobs)
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

/** Legacy workflow-start capability. */
internal class AuthorizedLegacyWebJobStart internal constructor(
    private val jobs: WebJobService,
) {
    fun start(jobId: String, workflow: WebWorkflow): WebWorkflowAdmission = jobs.start(jobId, workflow)
}

/** Versioned start capability; caller input cannot select paths, adapters or commands. */
internal class AuthorizedWebWorkflowStart internal constructor(private val jobs: WebJobService) {
    fun request(jobId: String, expectedJobVersion: String, request: NewWorkflowAttempt,
        requestKey: String): DurableWebWorkflowStartResult =
        jobs.requestDurableStart(jobId, expectedJobVersion, request, requestKey)
}

/** Cancellation-only capability; the body cannot select the authenticated actor. */
internal class AuthorizedWebCancellation internal constructor(
    private val session: AuthorizedWebSession,
    private val jobs: WebJobService,
) {
    fun request(jobId: String, runId: String, expectedRunVersion: String,
        requestKey: String): WorkflowCancellationRequestResult = jobs.requestDurableCancellation(
            jobId, runId, expectedRunVersion, WorkflowCancellationActor.browserSession(session.sessionId), requestKey,
        )
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
