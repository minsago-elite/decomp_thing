import type { Job } from '../api/generated';

const jobStatusLabels: Record<Job['status'], string> = {
  uploaded: 'Uploaded', queued: 'Queued', running: 'Running', completed: 'Completed',
  failed: 'Failed', cancelled: 'Cancelled', interrupted: 'Interrupted', unknown: 'Unknown',
};

export function formatJobStatus(status: Job['status']): string { return jobStatusLabels[status]; }

// Keep the canonical decimal value intact; Number would round valid uint64 values.
export function formatExactBytes(value: string): string { return `${value} bytes`; }

// Keep the source offset and every fractional digit, while making UTC readable.
export function formatExactTimestamp(value: string): string {
  const displayed = value.replace('T', ' ');
  return displayed.endsWith('Z') ? `${displayed.slice(0, -1)} UTC` : displayed;
}
