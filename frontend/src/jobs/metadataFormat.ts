import { commonCopy, jobStatusLabels } from '../copy/common';
import { textMessage } from '../shared/messages';
import type { Job } from '../api/generated';


export function formatJobStatus(status: Job['status']): string { return jobStatusLabels[status]; }

// Keep the canonical decimal value intact; Number would round valid uint64 values.
export function formatExactBytes(value: string): string { return textMessage(commonCopy.bytes, { value }); }

// Preserve source offsets and fractional digits; the API accepts either marker case.
export function formatExactTimestamp(value: string): string {
  const displayed = value.replace(/[Tt]/, ' ');
  return /[Zz]$/.test(displayed) ? `${displayed.slice(0, -1)} UTC` : displayed;
}
