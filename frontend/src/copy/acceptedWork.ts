// View-scoped interface copy; protocol values and DOM identities stay in their components.

export const acceptedWorkCopy = {
  "title": "Current and accepted work",
  "latestTitle": "Latest attempt",
  "noLatest": "No attempt is recorded for this job yet.",
  "latest": "Latest recorded attempt: {runId}. Its progress and reports belong to that attempt; they do not replace the accepted reconstruction below.",
  "latestActivity": "Follow latest attempt activity",
  "latestEvidence": "Latest attempt evidence and reports",
  "acceptedTitle": "Accepted reconstruction",
  "noAccepted": "No accepted revision is recorded for this job. A completed attempt is not an accepted reconstruction.",
  "locating": "Locating the attempt that recorded accepted revision {revisionId}…",
  "accepted": "Accepted revision {revisionId} was recorded by attempt {runId}. Newer attempts keep their own identities and do not replace it.",
  "acceptedAttempt": "Open the accepted attempt",
  "acceptedEvidence": "Accepted attempt evidence and report snapshots",
  "acceptedSources": "Browse accepted revision sources",
  "notFound": "Accepted revision {revisionId} is recorded, but the attempt that recorded it is not among the newest {count} recorded attempts. Browse attempt history to find it.",
  "lookupFailed": "The attempt that recorded the accepted revision could not be read. The accepted revision identity above is unchanged.",
  "lookupSession": "Reconnect the local session to locate the accepted attempt.",
  "lookupUnverified": "Attempt history could not be verified, so no accepted attempt is shown.",
  "retry": "Retry locating the accepted attempt"
} as const;
