import type { WebEvent } from '../api/generated';
import { ObservedUsage } from './ObservedUsage';
import { runPath } from '../app/paths';

export type ActivityGroup = 'stages' | 'messages' | 'plans' | 'tools' | 'usage' | 'other';
export function activityGroup(event: WebEvent): ActivityGroup {
  if (event.type === 'run.state') return 'stages';
  if (event.type === 'agent.message') return 'messages';
  if (event.type !== 'workflow.observation') return 'other';
  switch (event.payload.observationKind) {
    case 'workflow_phase': case 'workflow_run_state': return 'stages';
    case 'message': return 'messages';
    case 'plan': return 'plans';
    case 'context_usage': case 'agent_finished': return 'usage';
    case 'tool': case 'permission': case 'file_change': return 'tools';
    default: return 'other';
  }
}

export function matchesActivity(event: WebEvent, group: 'all' | ActivityGroup, task: string): boolean {
  if (group !== 'all' && group !== activityGroup(event)) return false;
  if (!task) return true;
  if (event.type !== 'workflow.observation') return false;
  const fields = event.payload.fields;
  return (fields.taskId?.includes(task) ?? false) || (fields.taskIdSha256?.includes(task) ?? false);
}

export function ActivityRow({ event, basePath }: { event: WebEvent; basePath: string }) {
  return <li class="activity-row">
    <time dateTime={event.occurredAt}>{event.occurredAt}</time>{' '}<span>Sequence {event.sequence}</span>
    <p><a href={runPath(basePath, event.jobId, event.runId)}>Attempt {event.runId}</a></p>
    {event.type === 'workflow.observation' ? <>
      <p>Observed {event.payload.observationKind}{event.payload.fields.phase ? `: ${event.payload.fields.phase}` : ''}</p>
      {event.payload.fields.status && <p>Observed status: {event.payload.fields.status}</p>}
      <p>Writer: {event.payload.writerId}. Task: {event.payload.fields.taskId ?? 'Not recorded'}. Revision: {event.payload.fields.revisionId ?? 'Not recorded'}.</p>
      {event.payload.observationKind === 'plan' && <p>Plan entries reported: {event.payload.fields.entryCount ?? 'Not recorded'}. Retained entry metadata: {event.payload.fields.entries?.length ?? 'Not recorded'}. {event.payload.fields.entriesTruncated && 'Producer truncated plan entries.'}</p>}
      <p>Fields omitted: {event.payload.omittedFieldCount}. {event.payload.fields.sourceSequenceGap && 'Source sequence gap reported.'} {event.payload.fields.textOmitted && 'Producer omitted text.'} {event.payload.fields.messageTrackingExhausted && 'Producer message tracking limit reached.'}</p>
      <ObservedUsage observation={event.payload} occurredAt={event.occurredAt} sequence={event.sequence} />
      <details>
        <summary>Correlation details for sequence {event.sequence}</summary>
        <p>These are recorded references. Task, session and revision evidence pages are not available from this view.</p>
        <dl class="job-facts">
          <dt>Task digest</dt><dd><code>{event.payload.fields.taskIdSha256 ?? 'Not recorded'}</code></dd>
          <dt>Session digest</dt><dd><code>{event.payload.fields.sessionIdSha256 ?? 'Not recorded'}</code></dd>
          <dt>Revision digest</dt><dd><code>{event.payload.fields.revisionIdSha256 ?? 'Not recorded'}</code></dd>
          <dt>Turn</dt><dd><code>{event.payload.fields.turnId ?? 'Not recorded'}</code></dd>
          <dt>Request digest</dt><dd><code>{event.payload.fields.requestSha256 ?? 'Not recorded'}</code></dd>
          <dt>Tool call digest</dt><dd><code>{event.payload.fields.toolCallIdSha256 ?? 'Not recorded'}</code></dd>
        </dl>
      </details>
    </> : <p>{event.type} metadata retained; content is not displayed in this observation view.</p>}
  </li>;
}
