// View-scoped interface copy; protocol values and DOM identities stay in their components.

export const supportExportCopy = {
  "supportExport": "Support export",
  "intro": "Prepare a redacted diagnostic document to share when reporting a problem. Nothing is collected until you preview it, and the download is exactly the previewed document.",
  "scope": "Export scope",
  "serverScope": "Server runtime, limits, recovery files and recent audit entries",
  "jobScope": "One job, its attempts and its audit entries",
  "jobId": "Job ID (32 lowercase hexadecimal characters)",
  "invalidJobId": "Enter a 32-character lowercase hexadecimal job ID.",
  "preview": "Preview export",
  "previewing": "Preparing preview…",
  "previewFailed": "The support export could not be prepared.",
  "previewReady": "Preview ready. Review it before downloading.",
  "generatedAt": "Generated",
  "redactionVersion": "Redaction policy",
  "includedSections": "Included sections",
  "omittedSections": "Omitted sections",
  "omission": "{section}: {reason}",
  "noSections": "No sections could be read.",
  "document": "Previewed document",
  "download": "Download previewed export ({bytes})",
  "tooLarge": "This preview exceeds the download limit; narrow the scope.",
  "reasonNotInScope": "outside the selected scope",
  "reasonUnavailable": "could not be read; its state is unknown",
  "reasonJobContent": "job content is never exported",
  "reasonPrivateConfiguration": "private server configuration is never exported",
  "reasonSecret": "credentials are never exported",
  "reasonNotRecorded": "not recorded by this application"
} as const;

export const runtimeCopy = {
  "reason": "Reason: {reason}",
  "application": "Application",
  "runtimeStatus": "Runtime status",
  "pageBuildIdentity": "Page build identity",
  "theseValuesIdentifyTheApplicationThatServedThisPage": "These values identify the application that served this page.",
  "applicationVersion": "Application version",
  "uiBuild": "UI build",
  "connectedServer": "Connected server",
  "reportedWhenTheLocalSessionWasCheckedOpeningThisView": "Reported when the local session was checked. Opening this view does not run tools or workflows.",
  "theServerReportsADifferentUIBuildReloadTheApplication": "The server reports a different UI build. Reload the application to load its current views.",
  "readiness": "Readiness",
  "serverBuild": "Server build",
  "serverInstance": "Server instance",
  "java": "Java",
  "platform": "Platform",
  "git": "Git",
  "maximumUpload": "Maximum upload",
  "workflowCapabilities": "Workflow capabilities",
  "noCapabilitiesReported": "No capabilities reported.",
  "runtimeInformationIsNotConnected": "Runtime information is not connected",
  "connectALocalSessionToSeeReportedToolAvailabilityAnd": "Connect a local session to see reported tool availability and workflow capabilities. Opening this page does not run a tool or check a provider.",
  "unavailable": "Unavailable",
  "notReported": "Not reported",
  "uploadsUnavailable": "Uploads unavailable"
} as const;

export const schedulerSummaryCopy = {
  "sampled": "Server sample time: {time}. This is the sample retained at the last session check.",
  "webWorkflowScheduler": "Web workflow scheduler",
  "schedulerMeasurementsWereNotReported": "Scheduler measurements were not reported.",
  "schedulerMeasurementsAreUnavailableForTheExternallySuppliedExecutor": "Scheduler measurements are unavailable for the externally supplied executor.",
  "sourceTheApplicationSWebWorkflowExecutorCountsAreApproximate": "Source: the application's web workflow executor. Counts are approximate aggregate observations, sampled independently.",
  "schedulerLifecycle": "Scheduler lifecycle",
  "activeWorkersCount": "Active workers (count)",
  "workerLimitCount": "Worker limit (count)",
  "queuedTasksCount": "Queued tasks (count)",
  "queueCapacityTasks": "Queue capacity (tasks)",
  "aTaskSQueuePositionAndStartTimeAreNot": "A task's queue position and start time are not reported. Free capacity does not establish workflow availability or authorize admission. These counts exclude host-wide resource diagnostics."
} as const;

export const progressRetentionSummaryCopy = {
  "sampled": "Sampled at {time} during the last session check. These counters cover this server process and reset on restart.",
  "progressHistoryRetention": "Progress history retention",
  "progressRetentionStatusWasNotReported": "Progress retention status was not reported.",
  "completedAttemptChecksCount": "Completed attempt checks (count)",
  "journalsExpiredCount": "Journals expired (count)",
  "failedChecksCount": "Failed checks (count)",
  "lastRecordedFailure": "Last recorded failure",
  "timedCleanupWaitsAtLeast24HoursAfterAnAttempt": "Timed cleanup waits at least 24 hours after an attempt ends. Journal size limits can omit older observations sooner. Cleanup visits eligible history in bounded batches; it does not promise an exact expiry time. Active work, pending publication and pinned progress remain protected. Pin controls are on each attempt page.",
  "countsIncludeRepeatedChecksNotUniqueJobsOrDiskUsage": "Counts include repeated checks, not unique jobs or disk usage. These rules concern progress history, not complete jobs or evidence archives.",
  "periodicProgressCleanupIsEnabled": "Periodic progress cleanup is enabled.",
  "periodicProgressCleanupIsDisabled": "Periodic progress cleanup is disabled.",
  "noneRecorded": "None recorded"
} as const;
