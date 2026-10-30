import { useEffect, useState } from 'preact/hooks';
import type { ModuleProgress as Progress, ModuleStage } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { moduleProgressCopy as copy } from '../copy/attempt';
import { usePrivateTransport } from '../session/PrivateTransport';
import { message, textMessage } from '../shared/messages';

const stageLabels = { analysis: copy.analysis, planning: copy.planning, generation: copy.generation, validation: copy.validation,
  publication: copy.publication } satisfies Record<ModuleStage['stage'], string>;
const stateLabels = { pending: copy.pending, active: copy.active, completed: copy.completed, stopped: copy.stopped,
  'not-reached': copy['not-reached'] } satisfies Record<ModuleStage['state'], string>;
const outcomeLabels = { 'plan-recorded': copy['plan-recorded'], 'build-passed': copy['build-passed'], 'build-failed': copy['build-failed'],
  'candidate-recorded': copy['candidate-recorded'], accepted: copy.accepted } satisfies Record<NonNullable<ModuleStage['outcome']>, string>;
type Compatibility = NonNullable<Progress['recovery']>['options'][number];
const compatibilityLabels = { compatible: copy.compatible, stale: copy.stale, incompatible: copy.incompatible,
  unknown: copy.unknown } satisfies Record<Compatibility['compatibility'], string>;

function Stage({ item }: { item: ModuleStage }) {
  return <li>
    <strong>{stageLabels[item.stage]}</strong>{': '}{stateLabels[item.state]}
    {item.completedUnits !== null && item.totalUnits !== null && <>{' ('}{textMessage(copy.units, { completed: item.completedUnits, total: item.totalUnits })}{')'}</>}
    {item.outcome && <>{'; '}{outcomeLabels[item.outcome]}</>}
  </li>;
}

/**
 * Stage-separated progress of one reconstruction attempt, read explicitly from its own retained reports.
 * The recovery section explains whether the retained plan could be reused; it never starts work.
 */
export function ModuleProgress({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const [request, setRequest] = useState(0);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!request) return;
    const controller = new AbortController(); setLoading(true); setError('');
    void client.get('moduleProgress', `/jobs/${jobId}/runs/${runId}/reports/module-progress`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.binding.jobId !== jobId || response.data.binding.runId !== runId) { setProgress(null); setError(copy.mismatch); return; }
      setProgress(response.data);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) { setProgress(null); setError(withApiFailureReference(copy.failed, failure)); }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, runId, request]);
  const unresolved = progress?.unresolved ?? null;
  const recovery = progress?.recovery ?? null;
  return <section aria-labelledby="module-progress-title">
    <h2 id="module-progress-title">{copy.title}</h2>
    <button type="button" disabled={loading} onClick={() => setRequest(value => value + 1)}>{request ? copy.refresh : copy.read}</button>
    <div aria-live="polite">{loading && <p role="status">{copy.reading}</p>}</div>
    {error && <p role="alert">{error}</p>}
    {progress && <>
      <p>{message(copy.source, { version: <code>{progress.attemptVersion}</code> })}</p>
      {progress.state === 'not-recorded' && <p>{copy.notRecorded}</p>}
      {progress.stages.length > 0 && <ol aria-label={copy.stages}>{progress.stages.map(item => <Stage key={item.stage} item={item} />)}</ol>}
      {progress.lastGeneratedModuleId && <p>{message(copy.lastGeneratedModule, { module: <code>{progress.lastGeneratedModuleId}</code> })}</p>}
      <h3>{copy.plan}</h3>
      {progress.plan ? <dl class="job-facts">
        <dt>{copy.planDigest}</dt><dd><code>{progress.plan.sha256}</code></dd>
        <dt>{copy.planModules}</dt><dd>{progress.plan.moduleCount}</dd>
        {progress.plan.profileId && <><dt>{copy.planProfile}</dt><dd><code>{progress.plan.profileId}</code></dd></>}
      </dl> : <p>{copy.noPlan}</p>}
      {unresolved && <>
        <h3>{copy.unresolvedTitle}</h3>
        <p>{unresolved.moduleCount === null ? copy.unresolvedUnknown : unresolved.moduleCount === '0' ? copy.unresolvedNone
          : textMessage(copy.unresolvedCount, { count: unresolved.moduleCount })}</p>
        {unresolved.moduleIds.length > 0 && <ul aria-label={copy.unresolvedTitle}>
          {unresolved.moduleIds.map(id => <li key={id}><code>{id}</code></li>)}
        </ul>}
        {unresolved.truncated && <p>{textMessage(copy.unresolvedTruncated, { shown: unresolved.moduleIds.length })}</p>}
        {unresolved.entityCount !== null && <p>{textMessage(copy.unresolvedEntities, { count: unresolved.entityCount })}</p>}
      </>}
      {recovery && <>
        <h3>{copy.recoveryTitle}</h3>
        {recovery.reasonCode ? <p>{copy.recoveryUnavailable[recovery.reasonCode]}</p> : <>
          {recovery.retainedModules !== null && <p>{textMessage(copy.retained, { modules: recovery.retainedModules })}</p>}
          {recovery.recordedContextCharacters !== null && <p>{textMessage(copy.recordedContext, { characters: recovery.recordedContextCharacters })}</p>}
          <p>{copy.compatibilityIntro}</p>
          <ul aria-label={copy.recoveryTitle}>{recovery.options.map(option => <li key={option.optionId}>
            <code>{option.optionId}</code>{': '}{compatibilityLabels[option.compatibility]}
            {option.reasonCode && <>{' '}{copy.reasons[option.reasonCode]}</>}
          </li>)}</ul>
        </>}
        <p>{copy.recoveryBoundary}</p>
      </>}
    </>}
  </section>;
}
