import { Fragment } from 'preact';
import { useState } from 'preact/hooks';
import { activityRowCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../copy/format';
import type { WebEvent } from '../api/generated';
import { ObservedUsage } from './ObservedUsage';
import { runPath } from '../app/paths';
import { additionalProgressReferences } from './progressReferences';

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

export function matchesActivity(event: WebEvent, group: 'all' | ActivityGroup, taskDigest: string): boolean {
  if (group !== 'all' && group !== activityGroup(event)) return false;
  if (!taskDigest) return true;
  if (event.type !== 'workflow.observation') return false;
  return event.payload.fields.taskIdSha256?.includes(taskDigest) ?? false;
}

export function ActivityRow({ event, basePath, selected = false, inspectionHref }: { event: WebEvent; basePath: string; selected?: boolean; inspectionHref?: string }) {
  const [referencesOpen, setReferencesOpen] = useState(false);
  return <li class="activity-row" aria-current={selected ? 'true' : undefined}>
    <time dateTime={event.occurredAt} title={event.occurredAt}>{formatExactTimestamp(event.occurredAt)}</time>{' '}<span>{displayMessage(copy.sequence, { sequence: event.sequence })}</span>
    <p><a href={runPath(basePath, event.jobId, event.runId)}>{displayMessage(copy.attempt, { run: event.runId })}</a></p>
    {selected && <p>{copy.selectedObservation}</p>}
    {inspectionHref && <p><a href={inspectionHref}>{displayMessage(copy.inspectObservation, { sequence: event.sequence })}</a></p>}
    {event.type === 'workflow.observation' ? <>
      <p>{displayMessage(copy.observed, { kind: event.payload.observationKind, phase: event.payload.fields.phase ? displayMessage(copy.phase, { phase: event.payload.fields.phase }) : '' })}</p>
      {event.payload.fields.status && <p>{displayMessage(copy.observedStatus, { status: event.payload.fields.status })}</p>}
      <p>{displayMessage(copy.writer, { writer: event.payload.writerId })}</p>
      {event.payload.observationKind === 'plan' && <p>{displayMessage(copy.planEntries, { count: event.payload.fields.entryCount ?? copy.notRecorded, truncated: event.payload.fields.entriesTruncated ? copy.truncatedPlan : '' })}</p>}
      <p>{displayMessage(copy.omitted, { count: event.payload.omittedFieldCount, sequenceGap: event.payload.fields.sourceSequenceGap ? copy.sequenceGap : '', textOmitted: event.payload.fields.textOmitted ? copy.textOmitted : '', trackingExhausted: event.payload.fields.messageTrackingExhausted ? copy.trackingExhausted : '' })}</p>
      <ObservedUsage observation={event.payload} occurredAt={event.occurredAt} sequence={event.sequence} />
      <details>
        <summary>{displayMessage(copy.correlation, { sequence: event.sequence })}</summary>
        <p>{copy.theseAreRecordedReferencesTaskSessionAndRevisionEvidencePages}</p>
        <dl class="job-facts">
          <dt>{copy.taskDigest}</dt><dd><code>{event.payload.fields.taskIdSha256 ?? copy.notRecorded}</code></dd>
          <dt>{copy.sessionDigest}</dt><dd><code>{event.payload.fields.sessionIdSha256 ?? copy.notRecorded}</code></dd>
          <dt>{copy.revisionDigest}</dt><dd><code>{event.payload.fields.revisionIdSha256 ?? copy.notRecorded}</code></dd>
          <dt>{copy.turn}</dt><dd><code>{event.payload.fields.turnId ?? copy.notRecorded}</code></dd>
          <dt>{copy.requestDigest}</dt><dd><code>{event.payload.fields.requestSha256 ?? copy.notRecorded}</code></dd>
          <dt>{copy.toolCallDigest}</dt><dd><code>{event.payload.fields.toolCallIdSha256 ?? copy.notRecorded}</code></dd>
        </dl>
        <details onToggle={toggle => setReferencesOpen(toggle.currentTarget.open)}>
          <summary>{copy.additionalReferences}</summary>
          {referencesOpen && <>
            <p>{copy.referenceBoundary}</p>
            <dl class="job-facts">
              {additionalProgressReferences(event.payload.fields).map(reference => <Fragment key={reference.key}>
                <dt>{reference.label}</dt><dd><code>{reference.value}</code></dd>
              </Fragment>)}
            </dl>
          </>}
        </details>
      </details>
    </> : event.type === 'run.state' ? <>
      <p>{displayMessage(copy.recordedRunState, { state: event.payload.state })}</p>
      <p>{displayMessage(copy.recordedRunAcceptance, { acceptance: event.payload.acceptance })}</p>
    </> : <p>{displayMessage(copy.otherObservation, { type: event.type })}</p>}
  </li>;
}
