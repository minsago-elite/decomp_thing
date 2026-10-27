import type { ComponentChildren } from 'preact';
import type { Capability, Job } from '../api/generated';

/**
 * Settled, active, stopped (failed), blocked (not offered), pending and unknown states
 * share one mark vocabulary. The
 * label always carries the meaning; the shape repeats it for people scanning a list.
 */
export type StateTone = 'settled' | 'active' | 'stopped' | 'blocked' | 'pending' | 'unknown';

export function StateMark({ tone, children }: { tone: StateTone; children: ComponentChildren }) {
  return <span class="state-mark" data-tone={tone}>{children}</span>;
}

const jobTones = {
  uploaded: 'pending', queued: 'active', running: 'active', completed: 'settled',
  failed: 'stopped', cancelled: 'stopped', interrupted: 'stopped', unknown: 'unknown',
} as const satisfies Record<Job['status'], StateTone>;

const capabilityTones = {
  supported: 'settled', unavailable: 'blocked', unsupported: 'blocked', unknown: 'unknown',
} as const satisfies Record<Capability['state'], StateTone>;

export function jobStatusTone(status: Job['status']): StateTone { return jobTones[status]; }
export function capabilityTone(state: Capability['state']): StateTone { return capabilityTones[state]; }
