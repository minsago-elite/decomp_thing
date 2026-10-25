import { useEffect, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { structureCopy as copy } from '../copy/structure';
import { message } from '../shared/messages';
import type { EntityDetail, FunctionInventory, ModuleDetail, ModuleInventory, StructureNeighborhood, StructureScorecard } from '../api/generated';
import type { SourceSelection } from '../app/paths';
import { beginSourceRead, currentSourceRead } from '../sources/navigation';
import type { SourceReadState } from '../sources/navigation';
import { structureReadMessage } from './navigation';

export type StructureHeader = FunctionInventory | ModuleInventory | ModuleDetail | EntityDetail | StructureNeighborhood | StructureScorecard;

/** One latest-only read keyed by the complete URL selection. */
export function useStructureRead<T>(key: string, read: (signal: AbortSignal) => Promise<T>): [SourceReadState<T>, () => void] {
  const [refresh, setRefresh] = useState(0);
  const fullKey = `${key}/${refresh}`;
  const [state, setState] = useState<SourceReadState<T>>({ key: fullKey, state: 'loading' });
  useEffect(() => beginSourceRead(fullKey, read, setState), [fullKey]);
  return [currentSourceRead(state, fullKey), () => setRefresh(value => value + 1)];
}

function Context({ selected, data }: { selected: SourceSelection; data: StructureHeader | null }) {
  const record = (value: StructureHeader['model']) => value.path && value.sha256
    ? message(copy.recordDigest, { path: <bdi>{value.path}</bdi>, sha256: <code>{value.sha256}</code>, schema: value.schemaVersion ?? copy.notRecorded })
    : message(copy.recordState, { state: value.state, reason: value.stateReason ?? copy.notRecorded });
  return <dl class="job-facts" aria-label={copy.context}>
    <dt>{copy.job}</dt><dd><code>{selected.jobId}</code></dd>
    <dt>{copy.attempt}</dt><dd><code>{selected.runId}</code></dd>
    <dt>{copy.revision}</dt><dd><code>{selected.revisionId}</code></dd>
    {data && <>
      <dt>{copy.sourceDigest}</dt><dd><code>{data.sourceSha256}</code></dd>
      <dt>{copy.structureVersion}</dt><dd><code>{data.structureVersion}</code></dd>
      <dt>{copy.modelRecord}</dt><dd>{record(data.model)}</dd>
      <dt>{copy.planRecord}</dt><dd>{record(data.plan)}</dd>
    </>}
  </dl>;
}

/** Model and plan states are always stated; an unavailable record is never presented as an empty result. */
function States({ data }: { data: StructureHeader }) {
  return <>
    <p role={data.state === 'available' ? undefined : 'alert'}>{copy.states[data.state]}
      {data.stateReason && <> {message(copy.reason, { code: <code>{data.stateReason}</code> })}</>}</p>
    {data.state === 'available' && <p>{copy.planStates[data.plan.state]}
      {data.plan.stateReason && <> {message(copy.reason, { code: <code>{data.plan.stateReason}</code> })}</>}</p>}
    <p>{copy.assessment[data.recoveryAssessment]}</p>
    <details>
      <summary>{copy.capabilitiesTitle}</summary>
      <ul>{data.capabilities.map(item => <li key={item.id}>{copy.capabilityNames[item.id]}: {copy.capabilityStates[item.state]}
        {item.reason && <> ({message(copy.reason, { code: <code>{item.reason}</code> })})</>}</li>)}</ul>
    </details>
  </>;
}

/** Revision context, the boundary statement, refresh, read status and the recorded model/plan states. */
export function Frame({ selected, data, read, onRefresh, pinned, boundary = copy.boundary, children }: {
  selected: SourceSelection; data: StructureHeader | null; read: SourceReadState<unknown>; onRefresh: () => void; pinned?: boolean;
  boundary?: string; children?: ComponentChildren;
}) {
  return <>
    <Context selected={selected} data={data} />
    <p>{boundary}</p>
    {pinned && <p>{copy.pinnedNotice}</p>}
    <button type="button" disabled={read.state === 'loading'} onClick={onRefresh}>{copy.refresh}</button>
    {read.state === 'loading' && <p role="status">{copy.loading}</p>}
    {read.state === 'failed' && <p role="alert">{structureReadMessage(read.failure)}</p>}
    {data && <States data={data} />}
    {data && children}
  </>;
}
