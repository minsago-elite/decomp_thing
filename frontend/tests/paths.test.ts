import { describe, expect, it } from 'vitest';
import { apiPath, apiResourcePath, appPath, normalizeBasePath, validateResourceHref } from '../src/app/paths';

describe('deployment prefix', () => {
  it('normalizes root and nested base paths without changing route identity', () => {
    expect(normalizeBasePath('/')).toBe('');
    expect(normalizeBasePath('')).toBe('');
    expect(normalizeBasePath('/tools/decomp/')).toBe('/tools/decomp');
    expect(appPath(normalizeBasePath('/tools/decomp/'), '/runtime')).toBe('/tools/decomp/runtime');
  });

  it.each(['//other.example', 'https://other.example', '/../outside', '/foo?secret', '/foo#fragment', '/%2fhidden', '/foo//bar'])(
    'rejects a noncanonical prefix %s', (value) => {
      expect(() => normalizeBasePath(value)).toThrow('base path is invalid');
    },
  );
});

describe('versioned API URL construction', () => {
  it('normalizes UI and API prefixes once and retains encoded query text', () => {
    expect(appPath('/nested/tools/', '/')).toBe('/nested/tools/');
    expect(apiPath('/nested/tools/', '/jobs/Case_ID')).toBe('/nested/tools/api/v1/jobs/Case_ID');
    const route = '/jobs?q=two%20words%2B%252F&cursor=Cursor_9007199254740993';
    expect(apiPath('/nested/', route)).toBe(`/nested/api/v1${route}`);
    expect(apiPath('/', '/session')).toBe('/api/v1/session');
  });

  it('encodes decoded filter values once without converting opaque IDs or cursors', () => {
    const path = apiPath('/nested', '/jobs', { q: 'α + / %2F', cursor: 'Cursor_9007199254740993', limit: 50, absent: undefined });
    const query = new URL(path, 'http://example.invalid').searchParams;
    expect(query.get('q')).toBe('α + / %2F');
    expect(query.get('cursor')).toBe('Cursor_9007199254740993');
    expect(query.get('limit')).toBe('50');
    expect(query.has('absent')).toBe(false);
    expect(path).toContain('%252F');
    expect(apiPath('/nested', path.slice('/nested/api/v1'.length))).toBe(path);
  });

  it.each([
    'https://example.invalid/jobs', '//example.invalid/jobs', '/jobs/', '/jobs//same',
    '/jobs/../session', '/jobs/./same', '/jobs/%2F', '/jobs/%252F', '/jobs/%41',
    '/api/v1/jobs', '/nested/api/v1/jobs', '/jobs#bootstrap=secret', '/jobs\\same',
    '/jobs?', '/jobs?cursor=one&cursor=two', '/jobs?cursor=%', '/jobs?cursor=%ff',
    '/jobs?cursor=%00', '/jobs?cursor=one&&limit=1', '/jobs?%63ursor=value',
  ])('rejects ambiguous or noncanonical API input %s', (route) => {
    expect(() => apiPath('/nested/', route)).toThrow('resource URL is invalid');
  });

  it('bounds deployment prefixes, queries and unsafe numeric values', () => {
    expect(normalizeBasePath(`/${'a'.repeat(254)}/`)).toHaveLength(255);
    expect(() => normalizeBasePath(`/${'a'.repeat(255)}/`)).toThrow();
    expect(() => apiPath('/', '/jobs', { limit: Number.MAX_SAFE_INTEGER + 1 })).toThrow();
    expect(() => apiPath('/', '/jobs', { q: '\ud800' })).toThrow();
    expect(() => apiPath('/', '/jobs', { q: '\n' })).toThrow();
    expect(() => apiPath('/', '/jobs', { q: 'x'.repeat(4096) })).toThrow();
    expect(() => apiPath('/', '/jobs', Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, 'v'])))).toThrow();
    expect(() => apiPath('/', '/jobs?cursor=existing', { cursor: 'new' })).toThrow();
  });
});

describe('identity-bound event, snapshot and download links', () => {
  const snapshot = { kind: 'snapshot', jobId: 'Job_Case', runId: 'Run_9007199254740993' } as const;
  const events = { ...snapshot, kind: 'events' } as const;
  const artifact = { kind: 'artifact-content', jobId: 'Job_Case', artifactId: 'Artifact_1' } as const;

  it('constructs exact resource identities under root or nested deployment', () => {
    expect(apiResourcePath('/', snapshot)).toBe('/api/v1/jobs/Job_Case/runs/Run_9007199254740993/snapshot');
    const content = apiResourcePath('/nested/', artifact);
    expect(content).toBe('/nested/api/v1/jobs/Job_Case/artifacts/Artifact_1/content');
    expect(validateResourceHref('/nested', content, artifact)).toBe(content);
    const stream = apiResourcePath('/nested/', events, { after: 'Cursor_9007199254740993' });
    expect(stream).toContain('/events?after=Cursor_9007199254740993');
    const polling = apiResourcePath('/nested', events, { transport: 'poll', after: 'Cursor_Case', limit: 200 });
    expect(validateResourceHref('/nested/', polling, events)).toBe(polling);
    const reordered = apiResourcePath('/nested', events) + '?limit=50&after=Cursor%5FCase&transport=poll';
    expect(validateResourceHref('/nested', reordered, events)).toBe(reordered);
  });

  it('rejects links to a different origin, prefix, kind, or opaque identity', () => {
    const expected = apiResourcePath('/nested', artifact);
    for (const href of [
      `https://example.invalid${expected}`, `//example.invalid${expected}`, expected.slice(1),
      expected.replace('/nested/', '/other/'), expected.replace('/nested/', '/nested-other/'),
      expected.replace('Job_Case', 'Job_Other'), expected.replace('Artifact_1', 'Artifact_2'),
      expected.replace('Artifact_1', '%41rtifact_1'), expected.replace('Artifact_1', 'artifact_1'),
      `${expected}/`, `${expected}?download=1`, `${expected}#fragment`,
    ]) expect(() => validateResourceHref('/nested', href, artifact)).toThrow();
    expect(() => validateResourceHref('/nested', apiResourcePath('/nested', events), snapshot)).toThrow();
    expect(() => apiResourcePath('/', { ...artifact, artifactId: 'already%5Fencoded' })).toThrow();
  });

  it('limits event query fields to a single known cursor and bounded polling options', () => {
    const path = apiResourcePath('/nested', events);
    for (const query of ['after=one&after=two', 'token=credential', 'transport=stream', 'after=%252F',
      'transport=poll&limit=201', 'transport=poll&limit=01', 'transport=poll&limit=1.5', 'limit=20', 'after=']) {
      expect(() => validateResourceHref('/nested', `${path}?${query}`, events)).toThrow();
    }
    expect(() => apiResourcePath('/', events, { transport: 'poll', limit: 0 })).toThrow();
    expect(() => apiResourcePath('/', snapshot, { after: 'Cursor' })).toThrow();
    expect(() => apiResourcePath('/', artifact, { transport: 'poll' })).toThrow();
  });
});
