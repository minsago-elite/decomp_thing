import { storageSummaryCopy as copy } from '../copy/runtime';
import { textMessage } from '../shared/messages';
import { Fragment } from 'preact';
import { useContext, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';
import type { MaintenancePreview, StorageSummary as Summary } from '../api/generated';
import { PrivateSessionContext, usePrivateTransport } from '../session/PrivateTransport';
import type { BrowserSession } from '../session/session';
import { formatExactBytes, formatExactCount } from '../copy/format';

registerContractExtension(lazyContractSchema);

const CATEGORIES = ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other'] as const;

/** One endpoint's latest result. Each read clears only its own prior result (latest-only, never stale). */
type Panel<T> = { status: 'idle' } | { status: 'loading' } | { status: 'ready'; data: T } | { status: 'failed'; notice: string };
type Failure = 'session' | 'denied' | 'unavailable' | 'unverifiable' | 'limit' | 'transient';
const IDLE = { status: 'idle' } as const;

/** Fixed guidance per failure family; only a vetted request ID ever accompanies it. */
function storageFailureFamily(failure: unknown): Failure {
  if (!(failure instanceof ApiClientError)) return 'transient';
  const server = failure.serverCode ?? '';
  if (failure.status === 401 || ['SESSION_REQUIRED', 'SESSION_EXPIRED'].includes(server)) return 'session';
  if (server === 'STORE_LIMIT') return 'limit';
  if (failure.status === 403 || ['ACCESS_DENIED', 'CSRF_DENIED', 'ORIGIN_DENIED'].includes(server)) return 'denied';
  if (failure.status === 404 || failure.status === 501 || failure.code === 'unsupported_contract'
    || ['NOT_FOUND', 'CAPABILITY_UNAVAILABLE', 'UNSUPPORTED'].includes(server)) return 'unavailable';
  if (['invalid_json', 'invalid_response', 'invalid_headers', 'unexpected_response', 'response_too_large'].includes(failure.code)) return 'unverifiable';
  return 'transient';
}
const FAILURE_COPY: Record<Failure, string> = {
  session: copy.failedSession, denied: copy.failedDenied, unavailable: copy.failedUnavailable,
  unverifiable: copy.failedUnverifiable, limit: copy.failedLimit, transient: copy.failedTransient,
};
const failureNotice = (part: string, failure: unknown) =>
  withApiFailureReference(textMessage(copy.failedPart, { part, reason: FAILURE_COPY[storageFailureFamily(failure)] }), failure);

/** Explicit read-only reads: storage accounting and a maintenance dry run. Neither writes or starts work.
 * The two GETs are independent server reads with no shared snapshot, so each settles and renders on its own. */
export function StorageSummary({ basePath }: { basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const session = useContext(PrivateSessionContext);
  const [generation, setGeneration] = useState(() => viewGeneration(session));
  useLayoutEffect(() => {
    setGeneration(viewGeneration(session));
    return session?.subscribe(state => { setGeneration(state.status === 'authenticated' ? state.generation : null); });
  }, [session]);
  // Results are tagged with the binding that issued them; any other binding renders as unread, synchronously.
  const [view, setView] = useState<{ client: unknown; generation: number | null; summary: Panel<Summary>; preview: Panel<MaintenancePreview> }>(
    () => ({ client, generation, summary: IDLE, preview: IDLE }));
  const current = view.client === client && view.generation === generation;
  const summary = current ? view.summary : IDLE;
  const preview = current ? view.preview : IDLE;
  const active = useRef<AbortController | null>(null);
  useLayoutEffect(() => () => { active.current?.abort(); active.current = null; }, [client, generation]);

  function read() {
    if (active.current) return;
    const controller = new AbortController(); active.current = controller;
    const binding = { client, generation };
    const update = (change: (prior: typeof view) => Partial<typeof view>) => {
      if (active.current !== controller || controller.signal.aborted) return;
      setView(prior => prior.client === binding.client && prior.generation === binding.generation ? { ...prior, ...change(prior) } : prior);
    };
    setView({ ...binding, summary: { status: 'loading' }, preview: { status: 'loading' } });
    let open = 2;
    const settle = () => { open -= 1; if (open === 0 && active.current === controller) active.current = null; };
    client.get('storageSummary', '/storage', { signal: controller.signal }).then(
      response => { update(() => ({ summary: { status: 'ready', data: response.data } })); },
      (failure: unknown) => { update(() => ({ summary: { status: 'failed', notice: failureNotice(copy.storagePart, failure) } })); },
    ).finally(settle);
    client.get('maintenancePreview', '/storage/maintenance-preview', { signal: controller.signal }).then(
      response => { update(() => ({ preview: { status: 'ready', data: response.data } })); },
      (failure: unknown) => { update(() => ({ preview: { status: 'failed', notice: failureNotice(copy.maintenancePart, failure) } })); },
    ).finally(settle);
  }
  const busy = summary.status === 'loading' || preview.status === 'loading';
  const failures = [summary, preview].filter(panel => panel.status === 'failed').length;
  // One polite announcement per state change: reading, then a single outcome only when something failed.
  const notice = busy ? copy.reading : failures === 2 ? copy.failed : failures === 1 ? copy.partlyFailed : '';
  return <section aria-labelledby="storage-summary-title">
    <h3 id="storage-summary-title">{copy.storage}</h3>
    <p>{copy.explanation}</p>
    <button type="button" disabled={busy} onClick={read}>{copy.read}</button>
    <p role="status">{notice}</p>
    {summary.status === 'idle' && preview.status === 'idle' && <p>{copy.notRead}</p>}
    {summary.status !== 'idle' && <>
      <h4>{copy.storagePart}</h4>
      {summary.status === 'loading' && <p>{copy.waiting}</p>}
      {summary.status === 'failed' && <p>{summary.notice}</p>}
      {summary.status === 'ready' && <>
        {!summary.data.complete && <p>{copy.partial}</p>}
        {summary.data.complete && summary.data.jobCount === '0' && summary.data.totalBytes === '0' && <p>{copy.emptyStorage}</p>}
        <dl class="job-facts">
          <dt>{copy.total}</dt><dd>{formatExactBytes(summary.data.totalBytes)}</dd>
          <dt>{copy.jobs}</dt><dd>{summary.data.jobCount}</dd>
          {CATEGORIES.map(name => <Fragment key={name}><dt>{copy[name]}</dt><dd>{formatExactBytes(summary.data.categories[name].bytes)}</dd></Fragment>)}
          <dt>{copy.pendingDeletions}</dt><dd>{summary.data.pendingDeletions}</dd>
        </dl>
      </>}
    </>}
    {preview.status !== 'idle' && <>
      <h4>{copy.maintenance}</h4>
      {preview.status === 'loading' && <p>{copy.waiting}</p>}
      {preview.status === 'failed' && <p>{preview.notice}</p>}
      {preview.status === 'ready' && <>
        <p>{copy.automaticDeletionDisabled}</p>
        {preview.data.complete && preview.data.actions.length === 0 && preview.data.omittedActions === '0' && <p>{copy.emptyMaintenance}</p>}
        <p>{textMessage(copy.affected, { jobs: preview.data.affectedJobs, bytes: formatExactBytes(preview.data.reclaimableBytes) })}</p>
        <p>{textMessage(copy.protectedJobs, { count: formatExactCount((BigInt(preview.data.protectedJobs.length) + BigInt(preview.data.omittedProtectedJobs)).toString()) })}</p>
        {!preview.data.complete && <p>{copy.partial}</p>}
      </>}
    </>}
  </section>;
}

function viewGeneration(session: BrowserSession | null): number | null {
  const state = session?.snapshot();
  return state?.status === 'authenticated' ? state.generation : null;
}
