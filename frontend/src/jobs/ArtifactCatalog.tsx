import { useEffect, useRef, useState } from 'preact/hooks';
import type { Artifacts } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { artifactCopy as copy } from '../copy/artifacts';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { formatExactBytes } from './metadataFormat';

const ARTIFACT_PAGE_LIMIT = 50;

/** Route for one bounded catalog page; IDs and cursors are opaque and validated by the shared path builder. */
export function artifactCatalogRoute(jobId: string, runId: string, revisionId: string | null, cursor: string | null): string {
  const query = new URLSearchParams({ runId });
  if (revisionId !== null) query.set('revisionId', revisionId);
  query.set('limit', String(ARTIFACT_PAGE_LIMIT));
  if (cursor !== null) query.set('cursor', cursor);
  return `/jobs/${jobId}/artifacts?${query.toString()}`;
}

/** Withhold a page that is not the exact requested job, attempt and revision selection. */
export function bindArtifactCatalog(data: Artifacts, jobId: string, runId: string, revisionId: string | null): Artifacts {
  if (data.binding.jobId !== jobId || data.binding.runId !== runId || data.binding.revisionId !== revisionId
    || data.page.limit !== ARTIFACT_PAGE_LIMIT || data.items.some(item => item.family === undefined || item.verification === undefined)) {
    throw new ApiClientError('invalid_response');
  }
  return data;
}

function failureMessage(failure: unknown): string {
  let text: string = copy.failed;
  if (failure instanceof ApiClientError) {
    if (failure.status === 410 || failure.status === 409 || ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) text = copy.expired;
    else if (failure.status === 429) text = copy.busy;
  }
  return withApiFailureReference(text, failure);
}

/** Explicit, paged catalog read. Downloads use ordinary browser attachment links, never in-page blobs. */
export function ArtifactCatalog({ jobId, runId, revisionId, basePath }: { jobId: string; runId: string; revisionId: string | null; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const [selection, setSelection] = useState<{ request: number; revisionOnly: boolean; cursor: string | null }>({ request: 0, revisionOnly: false, cursor: null });
  const [state, setState] = useState<{ key: string; loading: boolean; data: Artifacts | null; error: string }>({ key: '', loading: false, data: null, error: '' });
  const filter = selection.revisionOnly ? revisionId : null;
  const key = [jobId, runId, filter, selection.cursor, selection.request].join('/');
  useEffect(() => {
    if (!selection.request) return undefined;
    const controller = new AbortController();
    setState({ key, loading: true, data: null, error: '' });
    void client.get('artifacts', artifactCatalogRoute(jobId, runId, filter, selection.cursor), { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      setState({ key, loading: false, data: bindArtifactCatalog(response.data, jobId, runId, filter), error: '' });
      heading.current?.focus();
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setState({ key, loading: false, data: null, error: failureMessage(failure) });
    });
    return () => { controller.abort(); };
  }, [client, key]);
  const current = state.key === key ? state : { key, loading: selection.request > 0, data: null, error: '' };
  const data = current.data;
  return <section aria-labelledby="artifact-catalog-title" class="artifact-catalog">
    <h2 id="artifact-catalog-title" ref={heading} tabIndex={-1}>{copy.title}</h2>
    <p>{copy.boundary}</p>
    {revisionId !== null && <label><input type="checkbox" checked={selection.revisionOnly} disabled={current.loading}
      onChange={event => setSelection(value => ({ request: value.request || 1, revisionOnly: (event.target as HTMLInputElement).checked, cursor: null }))} /> {copy.revisionOnly}</label>}
    <button type="button" disabled={current.loading} onClick={() => setSelection(value => ({ ...value, request: value.request + 1, cursor: null }))}>
      {selection.request ? copy.refresh : copy.read}</button>
    {current.loading && <p role="status">{copy.loading}</p>}
    {current.error && <p role="alert">{current.error}</p>}
    {data && <>
      <p role="status">{data.items.length ? message(copy.page, { count: data.items.length }) : copy.empty}</p>
      {data.unavailableFiles > 0 && <p><strong>{message(copy.unavailable, { count: data.unavailableFiles })}</strong></p>}
      <p>{copy.acceptance}</p>
      <ul class="job-list" aria-label={copy.title}>
        {data.items.map(item => <li key={item.artifactId}>
          <h3>{copy.family[item.family!]}</h3>
          <p class={item.verification === 'source-inventory-checked' ? 'artifact-inventory-checked' : 'artifact-unverified'}>
            <strong>{item.verification === 'source-inventory-checked' ? copy.inventoryChecked : copy.available}</strong></p>
          <dl class="job-facts">
            <dt>{copy.size}</dt><dd>{formatExactBytes(item.sizeBytes)}</dd>
            <dt>{copy.digest}</dt><dd><code>{item.sha256}</code></dd>
            <dt>{copy.mediaType}</dt><dd><code>{item.mediaType}</code></dd>
            <dt>{copy.role}</dt><dd>{item.role}</dd>
            <dt>{copy.revision}</dt><dd>{item.binding.revisionId === null ? copy.noRevision : <code>{item.binding.revisionId}</code>}</dd>
          </dl>
          <p>{copy.downloadCheck}</p>
          <a href={item.contentHref} download={item.displayName}
            aria-label={textMessage(copy.download, { name: item.displayName })}>{message(copy.download, { name: <bdi>{item.displayName}</bdi> })}</a>
        </li>)}
      </ul>
      <nav aria-label={copy.title}>
        <button type="button" disabled={selection.cursor === null} onClick={() => setSelection(value => ({ ...value, cursor: null }))}>{copy.first}</button>
        <button type="button" disabled={data.page.nextCursor === null} onClick={() => {
          if (data.page.nextCursor !== null) setSelection(value => ({ ...value, cursor: data.page.nextCursor }));
        }}>{copy.next}</button>
      </nav>
    </>}
  </section>;
}
