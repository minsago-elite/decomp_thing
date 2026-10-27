import type { Job } from '../api/generated';

export const commonCopy = {
  "bytes": "{value} bytes",
  "failureReference": "{message} Reference ID: {reference}."
} as const;

export const jobStatusLabels = {
  "uploaded": "Uploaded",
  "queued": "Queued",
  "running": "Running",
  "completed": "Completed",
  "failed": "Failed",
  "cancelled": "Cancelled",
  "interrupted": "Interrupted",
  "unknown": "Unknown"
} satisfies Record<Job['status'], string>;
