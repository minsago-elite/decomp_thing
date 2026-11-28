import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { Artifacts } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { artifactCopy as copy } from '../copy/artifacts';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { formatExactBytes } from './metadataFormat';
import { isDeletedJob } from '../shared/retainMetadata';

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
    || data.page.limit !== ARTIFACT_PAGE_LIMIT || data.items.some(item => item.family === undefined || item.verification === undefined || item.content === undefined)) {
    throw new ApiClientError('invalid_response');
  }
  return data;
}

const CURSOR = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SCOPE_KEY = 'artifacts', CURSOR_KEY = 'artifactCursor';

/** The catalog scope and opaque server cursor saved in an attempt address; null means the list was not opened. */
export type ArtifactLocation = { scope: 'run' | 'revision'; cursor: string | null } | null;

function invalidLocation(): never { throw new Error('The saved artifact selection is invalid.'); }

/** Read only this catalog's keys; other attempt query state, such as validation selection, is left to its owner. */
export function artifactLocation(search: string): ArtifactLocation {
  if (search.length > 4096) return invalidLocation();
  const params = new URLSearchParams(search), scopes = params.getAll(SCOPE_KEY), cursors = params.getAll(CURSOR_KEY);
  if (scopes.length === 0) return cursors.length === 0 ? null : invalidLocation();
  const [scope] = scopes, [cursor] = cursors;
  if (scopes.length !== 1 || cursors.length > 1 || (scope !== 'run' && scope !== 'revision')
    || (cursor !== undefined && !CURSOR.test(cursor))) return invalidLocation();
  return { scope, cursor: cursor ?? null };
}

/** Replace only the catalog keys in the current attempt query. */
export function artifactRouteSearch(current: string, next: ArtifactLocation): string {
  const params = new URLSearchParams(current);
  params.delete(SCOPE_KEY); params.delete(CURSOR_KEY);
  if (next !== null) {
    params.set(SCOPE_KEY, next.scope);
    if (next.cursor !== null) params.set(CURSOR_KEY, next.cursor);
  }
  const encoded = params.toString(), search = encoded ? `?${encoded}` : '';
  artifactLocation(search);
  return search;
}

type Selection = { request: number; revisionOnly: boolean; cursor: string | null };

/**
 * Inside the routed workbench the opened catalog, its revision filter and page live in the attempt URL, so Back,
 * Forward and reload restore them (#495). Opening, filtering and paging push history; Refresh replaces it. The legacy
 * embedding has no router and keeps the same selection in component state.
 */
function useCatalogSelection(revisionId: string | null): {
  selection: Selection; invalid: boolean; tooLong: boolean; select: (next: Selection, replace?: boolean) => void;
  /** Set by an explicit control so the next completed read moves focus with scrolling; restores keep the browser's scroll. */
  activated: { current: boolean };
} {
  const route = useLocation();
  const [local, setLocal] = useState<Selection>({ request: 0, revisionOnly: false, cursor: null });
  const [refresh, setRefresh] = useState(0);
  const [overflow, setOverflow] = useState<string | null>(null);
  const activated = useRef(false);
  if (!route.url) return { selection: local, invalid: false, tooLong: false, activated, select: next => { activated.current = true; setLocal(next); } };
  const address = new URL(route.url, window.location.origin);
  let saved: ArtifactLocation = null, invalid = false;
  try {
    saved = artifactLocation(address.search);
    if (saved?.scope === 'revision' && revisionId === null) { saved = null; invalid = true; }
  } catch { invalid = true; }
  const selection = saved === null ? { request: 0, revisionOnly: false, cursor: null }
    : { request: 1 + refresh, revisionOnly: saved.scope === 'revision', cursor: saved.cursor };
  return { selection, invalid, tooLong: overflow === address.search, activated, select: (next, replace = false) => {
    // A late click from a view the user already left must not rewrite another address.
    if (window.location.pathname !== address.pathname) return;
    const current = window.location.search;
    const target = { scope: next.revisionOnly && revisionId !== null ? 'revision' : 'run', cursor: next.cursor } as const;
    let search: string;
    // Other attempt query state can leave no room for the catalog keys; explain it rather than drop that state.
    try { search = artifactRouteSearch(current, target); } catch { setOverflow(current); return; }
    setOverflow(null);
    activated.current = true;
    let saved: ArtifactLocation = null;
    try { saved = artifactLocation(current); } catch { /* an invalid saved selection is replaced below */ }
    // Compare the parsed selection, not the raw query, whose key order other owners may change.
    if (saved !== null && saved.scope === target.scope && saved.cursor === target.cursor) { setRefresh(value => value + 1); return; }
    route.route(`${address.pathname}${search}`, replace || invalid);
  } };
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
export function ArtifactCatalog({ jobId, runId, revisionId, basePath, onDeleted }: {
  jobId: string; runId: string; revisionId: string | null; basePath: string;
  /** A RESOURCE_GONE tombstone ends the routed attempt rather than reading as an expired cursor (#512). */
  onDeleted?: (failure: unknown) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const deletedHandler = useRef(onDeleted); deletedHandler.current = onDeleted;
  const heading = useRef<HTMLHeadingElement>(null);
  const { selection, invalid, tooLong, select, activated } = useCatalogSelection(revisionId);
  const [state, setState] = useState<{ key: string; loading: boolean; data: Artifacts | null; error: string }>({ key: '', loading: false, data: null, error: '' });
  const filter = selection.revisionOnly ? revisionId : null;
  const key = [jobId, runId, filter, selection.cursor, selection.request].join('/');
  useEffect(() => {
    if (!selection.request) return undefined;
    const controller = new AbortController(), explicit = activated.current;
    activated.current = false;
    setState({ key, loading: true, data: null, error: '' });
    void client.get('artifacts', artifactCatalogRoute(jobId, runId, filter, selection.cursor), { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      setState({ key, loading: false, data: bindArtifactCatalog(response.data, jobId, runId, filter), error: '' });
      heading.current?.focus(explicit ? undefined : { preventScroll: true });
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      if (isDeletedJob(failure) && deletedHandler.current) { deletedHandler.current(failure); return; }
      setState({ key, loading: false, data: null, error: failureMessage(failure) });
    });
    return () => { controller.abort(); };
  }, [client, key]);
  const current = state.key === key ? state : { key, loading: selection.request > 0, data: null, error: '' };
  const data = current.data;
  return <section aria-labelledby="artifact-catalog-title" class="artifact-catalog">
    <h2 id="artifact-catalog-title" ref={heading} tabIndex={-1}>{copy.title}</h2>
    <p>{copy.boundary}</p>
    {invalid && <p role="alert">{copy.invalidSaved}</p>}
    {tooLong && <p role="alert">{copy.addressTooLong}</p>}
    {revisionId !== null && <label><input type="checkbox" checked={selection.revisionOnly} disabled={current.loading}
      onChange={event => { select({ request: selection.request || 1, revisionOnly: (event.target as HTMLInputElement).checked, cursor: null }); }} /> {copy.revisionOnly}</label>}
    <button type="button" disabled={current.loading} onClick={() => { select({ ...selection, request: selection.request + 1, cursor: null }, selection.request > 0); }}>
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
          {item.content?.projection === 'unavailable'
            ? <p class="artifact-projection-unavailable"><strong>{copy.projectionUnavailable}</strong></p>
            : <>
              <p>{item.content?.projection === 'redacted' ? copy.projectionRedacted : copy.downloadCheck}</p>
              <a href={item.contentHref} download={item.displayName}
                aria-label={textMessage(copy.download, { name: item.displayName })}>{message(copy.download, { name: <bdi>{item.displayName}</bdi> })}</a>
            </>}
        </li>)}
      </ul>
      <nav aria-label={copy.title}>
        <button type="button" disabled={selection.cursor === null} onClick={() => { select({ ...selection, cursor: null }); }}>{copy.first}</button>
        <button type="button" disabled={data.page.nextCursor === null} onClick={() => {
          if (data.page.nextCursor !== null) select({ ...selection, cursor: data.page.nextCursor });
        }}>{copy.next}</button>
      </nav>
    </>}
  </section>;
}
