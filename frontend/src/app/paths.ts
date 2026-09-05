const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const QUERY_KEY = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const MAX_URL_LENGTH = 4096;

function invalidUrl(): never { throw new Error('The application resource URL is invalid.'); }
function hasControl(value: string): boolean {
  return [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
}

/** A server-supplied deployment prefix, never an arbitrary URL. */
export function normalizeBasePath(value: string): string {
  if (value === '' || value === '/') return '';
  if (value.length > 256 || !/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\/?$/.test(value)
    || value.replace(/\/$/, '').length + 1 > 256) {
    throw new Error('The application base path is invalid.');
  }
  return value.replace(/\/$/, '');
}

export function appPath(basePath: string, route: '/' | '/runtime' | '/upload'): string {
  if (route !== '/' && route !== '/runtime' && route !== '/upload') return invalidUrl();
  return `${normalizeBasePath(basePath)}${route}`;
}

export type ApiQuery = Readonly<Record<string, string | number | undefined>>;

/** Values are decoded data. URLSearchParams encodes them once; callers never pre-encode IDs/cursors. */
function encodeQuery(query: ApiQuery): string {
  const params = new URLSearchParams();
  const entries = Object.entries(query);
  if (entries.length > 32) return invalidUrl();
  for (const [key, value] of entries) {
    if (value === undefined) continue;
    if (!QUERY_KEY.test(key) || (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0))) return invalidUrl();
    const text = String(value);
    if (text.length > MAX_URL_LENGTH || hasControl(text)) return invalidUrl();
    // Do not permit URLSearchParams to silently replace an unpaired surrogate.
    try { encodeURIComponent(text); } catch { return invalidUrl(); }
    params.append(key, text);
  }
  const encoded = params.toString();
  if (encoded) validateQuery(encoded);
  return encoded;
}

/** Validate existing encoded query text without decoding/re-encoding its opaque values. */
function validateQuery(query: string): Map<string, string> {
  if (!query || query.length > MAX_URL_LENGTH || /[^\x21-\x7e]|[#\\]/.test(query)) return invalidUrl();
  const entries = query.split('&');
  if (entries.length > 32) return invalidUrl();
  const result = new Map<string, string>();
  for (const entry of entries) {
    const split = entry.indexOf('=');
    const key = entry.slice(0, split);
    if (split < 1 || !QUERY_KEY.test(key) || result.has(key)) return invalidUrl();
    let value: string;
    try { value = decodeURIComponent(entry.slice(split + 1).replace(/\+/g, ' ')); } catch { return invalidUrl(); }
    if (hasControl(value)) return invalidUrl();
    result.set(key, value);
  }
  return result;
}

/** Construct a root-relative v1 URL. The route begins after /api/v1, with no encoded path segments. */
export function apiPath(basePath: string, route: string, query?: ApiQuery): string {
  const base = normalizeBasePath(basePath);
  if (route.length > MAX_URL_LENGTH) return invalidUrl();
  const split = route.indexOf('?');
  const pathname = split === -1 ? route : route.slice(0, split);
  if (!/^\/(?:[A-Za-z0-9][A-Za-z0-9_-]{0,127})(?:\/[A-Za-z0-9][A-Za-z0-9_-]{0,127})*$/.test(pathname)
    || pathname === '/api' || pathname.startsWith('/api/')
    || (base !== '' && pathname.startsWith(`${base}/api/`))) return invalidUrl();
  let search = split === -1 ? '' : route.slice(split + 1);
  if (split !== -1) {
    if (query !== undefined) return invalidUrl();
    validateQuery(search);
  } else if (query !== undefined) search = encodeQuery(query);
  const result = `${base}/api/v1${pathname}${search ? `?${search}` : ''}`;
  return result.length <= MAX_URL_LENGTH ? result : invalidUrl();
}

export type ApiResource =
  | { kind: 'events' | 'snapshot'; jobId: string; runId: string }
  | { kind: 'artifact-content'; jobId: string; artifactId: string };

export interface EventQuery {
  after?: string;
  transport?: 'poll';
  limit?: number;
}

function identifier(value: string): string {
  if (!ID.test(value)) return invalidUrl();
  return encodeURIComponent(value);
}

function eventQuery(query: Map<string, string>): void {
  if (query.has('limit') && query.get('transport') !== 'poll') return invalidUrl();
  for (const [key, value] of query) {
    if (key === 'after') { identifier(value); }
    else if (key === 'transport') { if (value !== 'poll') return invalidUrl(); }
    else if (key === 'limit') {
      if (!/^[1-9][0-9]{0,2}$/.test(value) || Number(value) > 200) return invalidUrl();
    } else return invalidUrl();
  }
}

/** URL construction only; schema availability does not establish a live event/download capability. */
export function apiResourcePath(basePath: string, resource: ApiResource, options?: EventQuery): string {
  const job = identifier(resource.jobId);
  const route = resource.kind === 'artifact-content'
    ? `/jobs/${job}/artifacts/${identifier(resource.artifactId)}/content`
    : `/jobs/${job}/runs/${identifier(resource.runId)}/${resource.kind}`;
  if (options !== undefined && resource.kind !== 'events') return invalidUrl();
  const query: ApiQuery | undefined = options === undefined ? undefined : { ...options };
  if (query !== undefined) {
    const encoded = encodeQuery(query);
    if (encoded) eventQuery(validateQuery(encoded));
  }
  return apiPath(basePath, route, query);
}

/** Accept only the expected deployment, resource family and exact opaque identities. */
export function validateResourceHref(basePath: string, href: string, resource: ApiResource): string {
  if (href.length > 1024) return invalidUrl();
  const expected = apiResourcePath(basePath, resource);
  const split = href.indexOf('?');
  const pathname = split === -1 ? href : href.slice(0, split);
  if (pathname !== expected) return invalidUrl();
  if (split !== -1) {
    if (resource.kind !== 'events') return invalidUrl();
    eventQuery(validateQuery(href.slice(split + 1)));
  }
  return href;
}

/** Persistent job routes use the JVM job-store identity grammar. */
export function jobPath(basePath: string, jobId: string): string {
  if (!/^[0-9a-f]{32}$/.test(jobId)) return invalidUrl();
  return `${normalizeBasePath(basePath)}/jobs/${jobId}`;
}

export function runPath(basePath: string, jobId: string, runId: string): string {
  if (!ID.test(runId)) return invalidUrl();
  return `${jobPath(basePath, jobId)}/runs/${runId}`;
}
