// View-scoped interface copy; protocol values and DOM identities stay in their components.

export const runHistoryCopy = {
  "state": "Attempt state: {state}. Acceptance: {acceptance}.",
  "pageCount": "{count} attempts on this page.",
  "newestRecordedAttemptsFirstThisListIsNotACount": "Newest recorded attempts first. This list is not a count of accepted reconstructions.",
  "refreshHistory": "Refresh history",
  "recordedAttempts": "Recorded attempts",
  "noDurableAttemptsAreRecordedForThisJobLegacyActivity": "No durable attempts are recorded for this job. Legacy activity does not have invented attempt identities.",
  "firstPage": "First page",
  "nextAttempts": "Next attempts",
  "attemptHistory": "Attempt history",
  "returnToJobOverview": "Return to job overview",
  "connectALocalSessionToViewAttemptHistory": "Connect a local session to view attempt history.",
  "theRequestedJobIdentityIsInvalid": "The requested job identity is invalid.",
  "theSavedHistoryPageIsInvalidRefreshHistoryToReturn": "The saved history page is invalid. Refresh history to return to the first page.",
  "attemptHistoryIsUnavailableCheckTheJobAndLocalSession": "Attempt history is unavailable. Check the job and local session.",
  "attemptHistoryChangedOrThisPageExpiredRefreshHistoryTo": "Attempt history changed or this page expired. Refresh history to begin again.",
  "attemptHistoryCouldNotBeLoadedRetryThisRead": "Attempt history could not be loaded. Retry this read.",
  "previouslyLoadedAttemptsMayBeOutdated": " Previously loaded attempts may be outdated.",
  "loadingAttemptHistory": "Loading attempt history…",
  "attemptHistoryPages": "Attempt history pages",
  "retryHistoryPage": "Retry this page",
  "refreshingAttemptHistory": "Refreshing attempt history… Previously loaded attempts may be outdated.",
  "reconnectToReadAttemptHistory": "Reconnect the local session to read attempt history, then refresh history.",
  "attemptHistoryAccessDenied": "Access to attempt history was denied. Check the local session and selected job.",
  "incompatibleHistoryResponse": "This interface cannot read the server's history format. Check the client and server versions, then refresh history.",
  "attemptHistoryCouldNotBeVerified": "Attempt history could not be verified. Refresh history or retry this page; unverified results are not shown."
} as const;
