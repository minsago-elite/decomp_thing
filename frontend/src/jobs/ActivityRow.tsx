import { Fragment } from 'preact';
import { useState } from 'preact/hooks';
import { activityRowCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import type { WebEvent } from '../api/generated';
import { ObservedUsage } from './ObservedUsage';
import { runPath, sourceDirectoryPath } from '../app/paths';
import { additionalProgressReferences } from './progressReferences';
import { activityCorrelationCopy as correlationCopy } from '../copy/activityCorrelation';
import { correlate, type IdentityDigests, type KnownIdentityKind } from './activityCorrelation';

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

type ReferenceKind = 'task' | 'session' | 'revision' | 'workflow';
const linkable: Record<ReferenceKind, readonly KnownIdentityKind[]> = {
  task: [], session: [], revision: ['result-revision'], workflow: ['previous-attempt'],
};
const unlinked = {
  task: correlationCopy.unlinkedTask, session: correlationCopy.unlinkedSession,
  revision: correlationCopy.unlinkedRevision, workflow: correlationCopy.unlinkedWorkflow,
} as const satisfies Record<ReferenceKind, string>;

/** One recorded reference with either an evidence link or an explicit reason there is none. */
function Reference({ kind, digest, identities, event, basePath, onSelectTask }: {
  kind: ReferenceKind; digest: string | undefined; identities: IdentityDigests | null; event: WebEvent; basePath: string;
  onSelectTask: ((digest: string) => void) | undefined;
}) {
  // Session and task digests are never compared with attempt or revision identities.
  const correlation = correlate(digest, kind === 'task' || kind === 'session' ? new Map() : identities, linkable[kind]);
  return <dd>
    <code>{digest ?? copy.notRecorded}</code>
    <br />
    {correlation.state === 'missing' ? correlationCopy.missing
      : correlation.state === 'pending' ? correlationCopy.pending
      : correlation.state === 'unlinked' ? <>
        {unlinked[kind]}
        {kind === 'task' && onSelectTask && digest && <>{' '}<button type="button" onClick={() => onSelectTask(digest)}>{correlationCopy.showTask}</button></>}
      </>
      : <>
        {correlationCopy.matched[correlation.identity.kind]}
        {correlation.state === 'linked' && correlation.identity.kind === 'result-revision' && <>{' '}
          <a href={sourceDirectoryPath(basePath, { jobId: event.jobId, runId: event.runId, revisionId: correlation.identity.id })}>{correlationCopy.browseResult}</a></>}
        {correlation.state === 'linked' && correlation.identity.kind === 'previous-attempt' && <>{' '}
          <a href={runPath(basePath, event.jobId, correlation.identity.id)}>{correlationCopy.openPrevious}</a></>}
      </>}
  </dd>;
}

export function ActivityRow({ event, basePath, selected = false, inspectionHref, identities = null, onSelectTask }: {
  event: WebEvent; basePath: string; selected?: boolean; inspectionHref?: string;
  identities?: IdentityDigests | null; onSelectTask?: (digest: string) => void;
}) {
  const [referencesOpen, setReferencesOpen] = useState(false);
  // Correlation rows materialize only while open, so a full page stays inexpensive to render.
  const [correlationOpen, setCorrelationOpen] = useState(false);
  const thought = event.type === 'workflow.observation' && event.payload.observationKind === 'message' && event.payload.fields.role === 'thought';
  return <li class="activity-row" aria-current={selected ? 'true' : undefined}>
    <time dateTime={event.occurredAt} title={event.occurredAt}>{formatExactTimestamp(event.occurredAt)}</time>{' '}<span>{displayMessage(copy.sequence, { sequence: event.sequence })}</span>
    <p><a href={runPath(basePath, event.jobId, event.runId)}>{displayMessage(copy.attempt, { run: event.runId })}</a></p>
    {selected && <p>{copy.selectedObservation}</p>}
    {inspectionHref && <p><a href={inspectionHref}>{displayMessage(copy.inspectObservation, { sequence: event.sequence })}</a></p>}
    {event.type === 'workflow.observation' ? <>
      <p>{displayMessage(copy.observed, { kind: event.payload.observationKind, phase: event.payload.fields.phase ? displayMessage(copy.phase, { phase: event.payload.fields.phase }) : '' })}</p>
      {thought && <p>{correlationCopy.thought}</p>}
      {event.payload.fields.status && <p>{displayMessage(copy.observedStatus, { status: event.payload.fields.status })}</p>}
      <p>{displayMessage(copy.writer, { writer: event.payload.writerId })}</p>
      {event.payload.observationKind === 'plan' && <p>{displayMessage(copy.planEntries, { count: event.payload.fields.entryCount ?? copy.notRecorded, truncated: event.payload.fields.entriesTruncated ? copy.truncatedPlan : '' })}</p>}
      <p>{displayMessage(copy.omitted, { count: event.payload.omittedFieldCount, sequenceGap: event.payload.fields.sourceSequenceGap ? copy.sequenceGap : '', textOmitted: event.payload.fields.textOmitted ? copy.textOmitted : '', trackingExhausted: event.payload.fields.messageTrackingExhausted ? copy.trackingExhausted : '' })}</p>
      <ObservedUsage observation={event.payload} occurredAt={event.occurredAt} sequence={event.sequence} />
      <details onToggle={toggle => setCorrelationOpen(toggle.currentTarget.open)}>
        <summary>{displayMessage(copy.correlation, { sequence: event.sequence })}</summary>
        {correlationOpen && <>
        <p>{copy.theseAreRecordedReferencesTaskSessionAndRevisionEvidencePages}</p>
        <dl class="job-facts">
          <dt>{copy.taskDigest}</dt><Reference kind="task" digest={event.payload.fields.taskIdSha256} identities={identities} event={event} basePath={basePath} onSelectTask={onSelectTask} />
          <dt>{copy.sessionDigest}</dt><Reference kind="session" digest={event.payload.fields.sessionIdSha256} identities={identities} event={event} basePath={basePath} onSelectTask={onSelectTask} />
          <dt>{copy.revisionDigest}</dt><Reference kind="revision" digest={event.payload.fields.revisionIdSha256} identities={identities} event={event} basePath={basePath} onSelectTask={onSelectTask} />
          <dt>{copy.workflowRunDigest}</dt><Reference kind="workflow" digest={event.payload.fields.workflowRunIdSha256} identities={identities} event={event} basePath={basePath} onSelectTask={onSelectTask} />
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
        </>}
      </details>
    </> : event.type === 'run.state' ? <>
      <p>{displayMessage(copy.recordedRunState, { state: event.payload.state })}</p>
      <p>{displayMessage(copy.recordedRunAcceptance, { acceptance: event.payload.acceptance })}</p>
    </> : <p>{displayMessage(copy.otherObservation, { type: event.type })}</p>}
  </li>;
}
