import type { ProgressObservation, Run, WebEvent } from '../api/generated';
import type { StateTone } from '../shared/StateMark';

/**
 * Display stages derived from retained observations. They describe what the journal reported;
 * the attempt's durable state and acceptance remain the separate authority.
 */
export type StageState = 'waiting' | 'running' | 'blocked' | 'validating' | 'accepted' | 'rolled-back'
  | 'completed' | 'cancelled' | 'failed' | 'unknown';

type Phase = NonNullable<ProgressObservation['fields']['phase']>;

const phaseStates = {
  analyzing: 'running', planning: 'running', agent_running: 'running',
  policy_checking: 'validating', build_validating: 'validating', behavior_validating: 'validating',
  // A provisional or compile-valid result still awaits its remaining checks.
  provisional: 'validating', compile_valid: 'validating',
  // Unresolved work could not proceed without further input or another attempt.
  unresolved: 'blocked',
  accepted: 'accepted', rolled_back: 'rolled-back', completed: 'completed', cancelled: 'cancelled',
  failed: 'failed', rejected: 'failed', exhausted: 'failed', resource_exhausted: 'failed', interrupted: 'failed',
} as const satisfies Record<Phase, StageState>;

const tones = {
  waiting: 'pending', running: 'active', blocked: 'blocked', validating: 'active', accepted: 'settled',
  'rolled-back': 'blocked', completed: 'settled', cancelled: 'stopped', failed: 'stopped', unknown: 'unknown',
} as const satisfies Record<StageState, StateTone>;

export function stageTone(state: StageState): StateTone { return tones[state]; }

/** The stage an individual observation reports, or null when it carries no stage meaning. */
export function observationStage(observation: ProgressObservation): StageState | null {
  const fields = observation.fields;
  if (fields.phase !== undefined) return Object.hasOwn(phaseStates, fields.phase) ? phaseStates[fields.phase] : 'unknown';
  switch (observation.observationKind) {
    case 'run_started': case 'task_started': return 'running';
    // A denied permission blocks the requested action until the producer reports another stage.
    case 'permission': return fields.decision === 'deny' ? 'blocked' : null;
    case 'agent_finished':
      if (fields.failureKind !== undefined) return 'failed';
      if (fields.stopReason === 'cancelled') return 'cancelled';
      if (fields.stopReason === 'limit_exhausted') return 'failed';
      return fields.validationPending ? 'validating' : 'completed';
    default: return null;
  }
}

/** Durable attempt state, never inferred from the journal. */
export function attemptStage(run: Pick<Run, 'state' | 'acceptance'>): StageState {
  switch (run.state) {
    case 'queued': return 'waiting';
    case 'running': return 'running';
    case 'cancelling': return 'blocked';
    case 'completed': return run.acceptance === 'accepted' ? 'accepted' : 'completed';
    case 'cancelled': return 'cancelled';
    case 'failed': case 'interrupted': return 'failed';
    default: return 'unknown';
  }
}

export interface TaskStage {
  /** Task identity commitment; null groups observations without a recorded task. */
  taskDigest: string | null;
  state: StageState;
  /** Sequence of the observation that set the state. */
  sequence: string;
  occurredAt: string;
  observations: number;
}

/** Latest stage per task, in first-observed order, with the count of retained rows. */
export function taskStages(events: readonly WebEvent[]): TaskStage[] {
  const stages = new Map<string | null, TaskStage>();
  for (const event of events) {
    if (event.type !== 'workflow.observation' || event.sequence === null) continue;
    const digest = event.payload.fields.taskIdSha256 ?? null;
    const reported = observationStage(event.payload);
    const previous = stages.get(digest);
    if (!previous) {
      stages.set(digest, { taskDigest: digest, state: reported ?? 'unknown', sequence: event.sequence, occurredAt: event.occurredAt, observations: 1 });
      continue;
    }
    previous.observations += 1;
    if (reported !== null) Object.assign(previous, { state: reported, sequence: event.sequence, occurredAt: event.occurredAt });
  }
  return [...stages.values()];
}

export type StageCounts = Record<StageState, number>;
export function stageCounts(stages: readonly TaskStage[]): StageCounts {
  const counts = Object.fromEntries(Object.keys(tones).map(state => [state, 0])) as StageCounts;
  for (const stage of stages) counts[stage.state] += 1;
  return counts;
}

/**
 * A completed fraction only when its denominator is authoritative: a bounded total that the
 * producer declares complete. Observed task counts are never a denominator because tasks that
 * have not started yet are not visible in the journal.
 */
export type ProgressMeasure =
  | { kind: 'percent'; completed: bigint; total: bigint; percent: number }
  | { kind: 'count'; completed: bigint };
export function progressMeasure(completed: bigint, total: { value: bigint; authoritative: boolean } | null): ProgressMeasure {
  if (completed < 0n) throw new RangeError('negative progress');
  if (!total || !total.authoritative || total.value <= 0n || completed > total.value) return { kind: 'count', completed };
  // Floor, so that 100% means every declared unit completed.
  const percent = Number((completed * 100n) / total.value);
  return { kind: 'percent', completed, total: total.value, percent };
}
