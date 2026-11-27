import type { Run } from '../api/generated';

type Reason = NonNullable<Run['terminalReason']>;

/** Each stop outcome keeps its own label; none is folded into a generic failure. */
export const stopOutcomeCopy = {
  COMPLETED: { label: 'Completed', detail: 'The workflow reported completion. Completion alone does not establish acceptance.' },
  NO_CHANGES: { label: 'Completed without changes', detail: 'The workflow finished and reported no changes.' },
  REFUSED: { label: 'Refused', detail: 'The agent or the scheduler refused the work; no workflow outcome was produced.' },
  CANCELLED: { label: 'Cancelled by request', detail: 'A recorded cancellation request stopped this attempt.' },
  LIMIT_EXHAUSTED: { label: 'Budget exhausted', detail: 'A configured budget such as tool calls, output bytes or tokens was used up.' },
  TIMED_OUT: { label: 'Timed out', detail: 'The wall-clock or idle deadline was reached.' },
  FAILED: { label: 'Workflow failed', detail: 'The workflow reported a failure outcome.' },
  INFRASTRUCTURE_FAILED: { label: 'Infrastructure failure', detail: 'The workflow could not report any outcome because its execution infrastructure failed.' },
  PROCESS_INTERRUPTED: { label: 'Interrupted by a service stop', detail: 'The application stopped or restarted before the attempt reported an outcome.' },
} as const satisfies Record<Reason, { label: string; detail: string }>;

export const attemptOutcomeCopy = {
  stopReason: 'Stop reason',
  stopDescription: '{label}. {detail} {recordedCode}',
  recordedCode: 'Recorded code {code}.',
  usageSource: 'Source: the attempt\'s terminal receipt, recorded at {time}. Provider measurement time: Not reported. Missing counters remain unknown.',
  usageWhileActive: 'Usage is recorded with the attempt\'s terminal receipt; none is available before the attempt ends.',
  limitsSource: 'Source: the configuration persisted when this attempt was created at {time}. Limits do not measure consumption or confer acceptance.',
} as const;

export const queuePositionCopy = {
  title: 'Queue position',
  read: 'Check queue position',
  onRequest: 'The queue position is sampled only when you check it.',
  reading: 'Checking queue position.',
  sampled: 'Sampled at {time}.',
  position: 'About {position} of {queued} queued tasks ({ahead} ahead).',
  workers: 'Workers busy: {active} of {limit}.',
  approximate: 'Approximate: queued work can be cancelled or stopped, workers start tasks independently and this sample is read separately from the attempt record. Other queued tasks are counted, never identified.',
  notQueued: 'This attempt is no longer queued; its recorded state is {state}.',
  external: 'Queue position is unavailable: an externally supplied executor runs this service\'s workflows.',
  notInQueue: 'Queue position is unavailable: the attempt is not in this process\'s queue. It may be starting or waiting for recovery.',
  failed: 'Queue position could not be read. The attempt state above remains the authority.',
} as const;
