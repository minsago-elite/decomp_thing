// #629 paired controls: real createApiClient + real JobOrganization/JobDeletion; only fetch is mocked.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import axe from 'axe-core';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { useMemo, useState } from 'preact/hooks';
import { beforeEach, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import type { Bootstrap, Job, JobDeletionPreview, Operation } from '../src/api/generated';
import { jobCopy, jobDeletionCopy, jobOrganizationCopy as copy } from '../src/copy/job';
import { JobDeletion, JobOrganization } from '../src/jobs/JobLifecycle';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { onLibraryChange } from '../src/jobs/libraryChannel';

const fx = <T,>(n: string): T => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${n}.json`), 'utf8')) as { data: T }).data;
const ref = '123e4567-e89b-42d3-a456-426614174000';
const CANARY = 'PRIVATE /srv/secret canary';
const base: Job = { ...fx<Job>('job-lossless'), label: null, archived: false };
const jobId = base.jobId;
const v1 = base.version;
type Step = () => Response;
const json = (kind: string, data: unknown, status = 200): Step => () => new Response(JSON.stringify({ apiVersion: 1, kind, requestId: ref, data }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': ref } });
const doc = (data: unknown, status = 200) => json('job', data, status);
const fail = (status: number, code: string): Step => () => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: ref,
  error: { code, message: CANARY, retryable: false, details: [], retryAfterMs: null } }),
{ status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': ref } });
const malformed = (status: number): Step => () => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: ref, error: { message: CANARY } }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': ref } });
const netdown: Step = () => { throw new TypeError('Failed to fetch'); };
const url = (i: unknown) => typeof i === 'string' ? i : i instanceof URL ? i.href : (i as Request).url;
function seq(...steps: Step[]) {
  return vi.fn<typeof fetch>().mockImplementation(() => {
    const next = steps.shift();
    if (!next) return Promise.reject(new Error('unexpected extra request'));
    try { return Promise.resolve(next()); } catch (e) { return Promise.reject(e instanceof Error ? e : new Error('step failed')); }
  });
}
type F = ReturnType<typeof seq>;
const log = (f: F) => f.mock.calls.map(c => `${c[1]?.method ?? 'GET'} ${new URL(url(c[0]), 'https://x.invalid').pathname}`);
const header = (f: F, i: number, name: string) => new Headers(f.mock.calls[i]?.[1]?.headers).get(name);
const body = (f: F, i: number): unknown => JSON.parse(f.mock.calls[i]?.[1]?.body as string);
const csrf = 'a'.repeat(43);
const sessionA = { csrf: () => csrf };
const sessionB = { csrf: () => csrf };
let current: { setJob: (j: Job) => void; setSession: (s: typeof sessionA) => void } | undefined;
function Org({ fetcher, onChanged = () => undefined, start = base }: { fetcher: typeof fetch; onChanged?: (j: Job) => void; start?: Job }) {
  const [job, setJob] = useState(start);
  const [session, setSession] = useState(sessionA);
  current = { setJob, setSession };
  const client = useMemo(() => createApiClient({ basePath: '/', fetch: fetcher }), [fetcher]);
  return <JobOrganization job={job} client={client} basePath="/" session={session} onChanged={j => { onChanged(j); setJob(j); }} />;
}
const input = () => screen.getByLabelText<HTMLInputElement>(/Display label/);
const box = () => screen.getByLabelText<HTMLInputElement>(copy.archived);
const save = () => fireEvent.click(screen.getByRole('button', { name: copy.save }));
const status = () => screen.getAllByRole('status')[0]!.textContent ?? '';
const settled = () => waitFor(() => expect(screen.getByRole('button', { name: copy.save })).toHaveProperty('disabled', false));
const noCanary = () => expect(document.body.textContent).not.toContain('PRIVATE');
beforeEach(() => {
  current = undefined;
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

it('normal save sends one exact guarded PATCH and one GET, then reports Saved from a bound confirming readback', async () => {
  const changed = vi.fn(); const hint = vi.fn(); const stop = onLibraryChange('/', hint);
  const fresh = { ...base, version: 'job_version_2', label: 'Mine', archived: true };
  const f = seq(doc(fresh), doc(fresh));
  render(<Org fetcher={f} onChanged={changed} />);
  fireEvent.input(input(), { target: { value: '  Mine ' } }); fireEvent.click(box()); save();
  expect(await screen.findByText(copy.saved)).toBeTruthy();
  expect(log(f)).toEqual([`PATCH /api/v1/jobs/${jobId}`, `GET /api/v1/jobs/${jobId}`]);
  expect(body(f, 0)).toEqual({ label: 'Mine', archived: true });
  expect(header(f, 0, 'If-Match')).toBe(`"${v1}"`);
  expect(header(f, 0, 'X-CSRF-Token')).toBe(csrf);
  expect(header(f, 0, 'Idempotency-Key')).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(header(f, 1, 'Idempotency-Key')).toBeNull();
  expect(changed).toHaveBeenCalledExactlyOnceWith(fresh);
  await waitFor(() => expect(hint).toHaveBeenCalledOnce());
  expect(input().value).toBe('Mine'); expect(box().checked).toBe(true);
  stop();
});

it('a legitimate concurrent later version that still carries the requested values confirms the save', async () => {
  const changed = vi.fn();
  const f = seq(doc({ ...base, version: 'job_version_2', label: 'Mine' }), doc({ ...base, version: 'zz_concurrent', label: 'Mine', archived: true }));
  render(<Org fetcher={f} onChanged={changed} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  expect(await screen.findByText(copy.saved)).toBeTruthy();
  expect(changed).toHaveBeenCalledWith(expect.objectContaining({ version: 'zz_concurrent' }));
  expect(f).toHaveBeenCalledTimes(2);
});

const other = 'f'.repeat(32);
it.each([
  ['foreign ack', [doc({ ...base, jobId: other, version: 'x_2', label: 'Mine' })], 1],
  ['ack with unchanged version', [doc({ ...base, label: 'Mine' })], 1],
  ['ack missing the requested label', [doc({ ...base, version: 'job_version_2', label: 'Else' })], 1],
  ['malformed ack document', [json('operation', { nope: true })], 1],
  ['foreign readback', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), doc({ ...base, jobId: other, version: 'x_9', label: 'Mine' })], 2],
  ['stale readback', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), doc(base)], 2],
  ['stale readback with requested values', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), doc({ ...base, label: 'Mine' })], 2],
  ['readback with a different version but other values', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), doc({ ...base, version: 'job_version_3', label: 'Else' })], 2],
  ['readback failure after ack', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), fail(503, 'INTERNAL')], 2],
  ['readback network loss after ack', [doc({ ...base, version: 'job_version_2', label: 'Mine' }), netdown], 2],
] as const)('%s is unconfirmed: never Saved, never adopted, no extra request', async (_name, steps, calls) => {
  const changed = vi.fn(); const hint = vi.fn(); const stop = onLibraryChange('/', hint);
  const f = seq(...steps);
  render(<Org fetcher={f} onChanged={changed} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await settled();
  expect(status()).toContain(copy.unconfirmed);
  expect(screen.queryByText(copy.saved)).toBeNull();
  expect(changed).not.toHaveBeenCalled();
  expect(f).toHaveBeenCalledTimes(calls);
  expect(input().value).toBe('Mine');
  expect(input().getAttribute('aria-invalid')).toBeNull();
  await new Promise(r => setTimeout(r, 20));
  if (calls === 1) expect(hint).not.toHaveBeenCalled();
  noCanary(); stop();
});

it('archive-only ack must agree with the requested archive value', async () => {
  const f = seq(doc({ ...base, version: 'job_version_2', archived: false }));
  render(<Org fetcher={f} />);
  fireEvent.click(box()); save();
  await settled();
  expect(status()).toContain(copy.unconfirmed);
  expect(f).toHaveBeenCalledTimes(1);
});

it('a decoded 412 keeps the typed label, adopts untouched archive and the new version for the next deliberate Save', async () => {
  const f = seq(fail(412, 'VERSION_CONFLICT'), doc({ ...base, version: 'job_version_9', label: 'Other <b>tab</b>', archived: true }),
    doc({ ...base, version: 'job_version_10', label: 'Mine2', archived: true }), doc({ ...base, version: 'job_version_10', label: 'Mine2', archived: true }));
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  expect(await screen.findByText(/changed in another tab or request/)).toBeTruthy();
  await screen.findByText(/current label is: Other <b>tab<\/b>/);
  expect(document.querySelector('b')).toBeNull();
  await waitFor(() => expect(box().checked).toBe(true));
  expect(input().value).toBe('Mine');
  expect(f).toHaveBeenCalledTimes(2);
  await new Promise(r => setTimeout(r, 20));
  expect(f).toHaveBeenCalledTimes(2); // nothing is resent automatically
  fireEvent.input(input(), { target: { value: 'Mine2' } }); // post-conflict edit is kept
  save();
  expect(await screen.findByText(copy.saved)).toBeTruthy();
  expect(header(f, 2, 'If-Match')).toBe('"job_version_9"');
  expect(body(f, 2)).toEqual({ label: 'Mine2' });
  expect(header(f, 0, 'Idempotency-Key')).not.toBe(header(f, 2, 'Idempotency-Key'));
  noCanary();
});

it('a decoded 412 keeps a toggled archive while adopting an untouched label', async () => {
  const f = seq(fail(412, 'VERSION_CONFLICT'), doc({ ...base, version: 'job_version_9', label: 'Other tab', archived: false }));
  render(<Org fetcher={f} />);
  fireEvent.click(box()); save();
  await screen.findByText(/current label is: Other tab/);
  await waitFor(() => expect(input().value).toBe('Other tab'));
  expect(box().checked).toBe(true);
});

it('a foreign or same-version 412 readback is not adopted and the guard is unchanged', async () => {
  const changed = vi.fn();
  const f = seq(fail(412, 'VERSION_CONFLICT'), doc({ ...base, jobId: other, version: 'x', label: 'X' }));
  render(<Org fetcher={f} onChanged={changed} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await settled();
  expect(status()).toContain(copy.changed);
  expect(status()).not.toContain('current version is shown');
  expect(changed).not.toHaveBeenCalled();
  expect(screen.queryByText(/current label is/)).toBeNull();
  expect(input().value).toBe('Mine');
});

it('a same-version or failed 412 readback asks for refresh without claiming the refreshed version is shown', async () => {
  for (const readback of [doc(base), netdown]) {
    const f = seq(fail(412, 'VERSION_CONFLICT'), readback);
    const view = render(<Org fetcher={f} />);
    fireEvent.input(input(), { target: { value: 'Mine' } }); save();
    await settled();
    expect(status()).toContain(copy.changed);
    expect(status()).not.toContain('current version is shown');
    expect(input().value).toBe('Mine');
    expect(f).toHaveBeenCalledTimes(2);
    view.unmount();
  }
});

it('a cancelled 412 readback reports an unconfirmed result without implying a write may have landed', async () => {
  let readbackSignal: AbortSignal | undefined;
  const f = vi.fn<typeof fetch>().mockImplementation((_url, init) => {
    if (init?.method === 'PATCH') return Promise.resolve(fail(412, 'VERSION_CONFLICT')());
    return new Promise((_resolve, reject) => {
      readbackSignal = init?.signal ?? undefined;
      readbackSignal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  });
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await waitFor(() => expect(f).toHaveBeenCalledTimes(2));
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  await act(() => { window.dispatchEvent(new Event('offline')); });
  await waitFor(() => expect(readbackSignal?.aborted).toBe(true));
  expect(document.body.textContent).toContain(copy.paused);
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  await act(() => { window.dispatchEvent(new Event('online')); });
  await waitFor(() => expect(document.body.textContent).toContain(copy.unconfirmed));
  expect(document.body.textContent).not.toContain('may have been written');
  expect(f).toHaveBeenCalledTimes(2);
  expect(input().value).toBe('Mine');
});

it('a different job or session resets draft ownership without leaking the old input', async () => {
  const f = seq();
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Draft for A' } }); fireEvent.click(box());
  current!.setJob({ ...base, jobId: other, version: 'b_1', label: 'Job B', archived: false });
  await waitFor(() => expect(input().value).toBe('Job B'));
  expect(box().checked).toBe(false);
  fireEvent.input(input(), { target: { value: 'Draft for B' } });
  current!.setSession(sessionB);
  await waitFor(() => expect(input().value).toBe('Job B'));
  expect(f).not.toHaveBeenCalled();
});

it('a newer version of the same job keeps dirty fields only', async () => {
  render(<Org fetcher={seq()} />);
  fireEvent.input(input(), { target: { value: 'Mine' } });
  current!.setJob({ ...base, version: 'job_version_5', label: 'Server', archived: true });
  await waitFor(() => expect(box().checked).toBe(true));
  expect(input().value).toBe('Mine');
});

it('decoded 422 VALIDATION_FAILED for a submitted label is field-attached and cleared by input', async () => {
  const f = seq(fail(422, 'VALIDATION_FAILED'));
  const { container } = render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain(copy.invalidLabel);
  expect(alert.textContent).toContain(ref);
  expect(input().getAttribute('aria-invalid')).toBe('true');
  expect(input().getAttribute('aria-errormessage')).toBe(alert.id);
  expect(input().getAttribute('aria-describedby')).toContain(alert.id);
  expect(input().value).toBe('Mine');
  const result = await axe.run(container, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] }, rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
  expect(result.violations.map(v => v.id)).toEqual([]);
  fireEvent.input(input(), { target: { value: 'Mine!' } });
  expect(screen.queryByRole('alert')).toBeNull();
  expect(input().getAttribute('aria-invalid')).toBeNull();
  expect(input().getAttribute('aria-errormessage')).toBeNull();
  noCanary();
});

it('archive-only 422 stays form-level and never marks the untouched label invalid', async () => {
  const f = seq(fail(422, 'VALIDATION_FAILED'));
  render(<Org fetcher={f} />);
  fireEvent.click(box()); save();
  await settled();
  expect(status()).toContain(copy.invalidChange);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(input().getAttribute('aria-invalid')).toBeNull();
});

it.each([['malformed 422', malformed(422)], ['undecoded 422 code', fail(422, 'SOMETHING_ELSE')]] as const)('%s is unverified, not field validation', async (_n, step) => {
  const f = seq(step);
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await settled();
  expect(status()).toContain(copy.unverified);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(input().getAttribute('aria-invalid')).toBeNull();
  expect(input().value).toBe('Mine');
  noCanary();
});

it('local label validation is field-attached, sends nothing and clears on input', async () => {
  const f = seq();
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'x'.repeat(121) } }); save();
  expect((await screen.findByRole('alert')).textContent).toBe(copy.invalidLabel);
  expect(input().getAttribute('aria-errormessage')).toBe('job-label-error');
  fireEvent.input(input(), { target: { value: 'ok' } });
  expect(screen.queryByRole('alert')).toBeNull();
  expect(f).not.toHaveBeenCalled();
});

it('network loss keeps input neutral; a manual re-save is a new key under the same If-Match', async () => {
  const f = seq(netdown, fail(412, 'VERSION_CONFLICT'), doc({ ...base, version: 'job_version_2', label: 'Mine' }));
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await settled();
  expect(status()).toContain(copy.failed);
  expect(input().value).toBe('Mine');
  expect(input().getAttribute('aria-invalid')).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  save();
  await waitFor(() => expect(f).toHaveBeenCalledTimes(3));
  expect(header(f, 0, 'Idempotency-Key')).not.toBe(header(f, 1, 'Idempotency-Key'));
  expect([header(f, 0, 'If-Match'), header(f, 1, 'If-Match')]).toEqual([`"${v1}"`, `"${v1}"`]);
});

it('a neutral failure does not invalidate the field and a missing CSRF token sends nothing', async () => {
  const f = seq(fail(503, 'STORAGE_UNAVAILABLE'));
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await settled();
  expect(status()).toContain(copy.storage);
  expect(input().getAttribute('aria-invalid')).toBeNull();
  const g = seq();
  const client = createApiClient({ basePath: '/', fetch: g });
  render(<JobOrganization job={base} client={client} basePath="/" session={{ csrf: () => '' }} onChanged={vi.fn()} />);
  fireEvent.input(screen.getAllByLabelText(/Display label/)[1]!, { target: { value: 'x' } });
  fireEvent.click(screen.getAllByRole('button', { name: copy.save })[1]!);
  expect(await screen.findByText(copy.denied)).toBeTruthy();
  expect(g).not.toHaveBeenCalled();
});

// Deletion: fixed copy for operation states and protection codes; raw server text never rendered.
const prev = fx<JobDeletionPreview>('job-deletion-preview');
const opFixture = fx<Operation>('operation-job-delete');
const op = (state: Operation['state']): Operation => ({ ...opFixture, jobId, state, endedAt: state === 'completed' ? opFixture.endedAt : null, message: CANARY });
function del(f: F, onDeleted = vi.fn()) {
  const client = createApiClient({ basePath: '/', fetch: f });
  render(<JobDeletion job={base} client={client} basePath="/" session={sessionA} onDeleted={onDeleted} />);
  fireEvent.click(screen.getByRole('button', { name: jobDeletionCopy.reviewDeletion }));
  return onDeleted;
}
it.each(['running', 'completed', 'recovery-required'] as const)('accepted %s deletion renders fixed state copy, hands off before the hint and focuses the heading', async state => {
  const order: string[] = [];
  const stop = onLibraryChange('/', () => order.push('hint'));
  const f = seq(json('jobDeletionPreview', { ...prev, jobId, version: v1 }), json('operation', op(state), 202));
  const deleted = del(f, vi.fn(() => { order.push('deleted'); }));
  fireEvent.input(await screen.findByRole('textbox'), { target: { value: prev.displayFilename } });
  fireEvent.click(screen.getByRole('button', { name: jobDeletionCopy.deletePermanently }));
  expect(await screen.findByText(jobDeletionCopy.operationStates[state])).toBeTruthy();
  expect(Boolean(screen.queryByText(jobDeletionCopy.stillRunning))).toBe(state === 'running');
  expect(log(f)).toEqual([`GET /api/v1/jobs/${jobId}/deletion-preview`, `DELETE /api/v1/jobs/${jobId}`]);
  expect(header(f, 1, 'If-Match')).toBe(`"${v1}"`);
  expect(header(f, 1, 'X-CSRF-Token')).toBe(csrf);
  expect(body(f, 1)).toEqual({ confirmJobId: jobId });
  expect(deleted).toHaveBeenCalledWith(expect.objectContaining({ state }));
  await waitFor(() => expect(order).toEqual(['deleted', 'hint']));
  expect(document.activeElement).toBe(screen.getByRole('heading', { name: jobDeletionCopy.deleteJob }));
  await new Promise(r => setTimeout(r, 20));
  expect(f).toHaveBeenCalledTimes(2);
  noCanary(); stop();
});

it('protections render fixed per-code copy with a generic fallback and never the server message', async () => {
  const protections = [{ code: 'UNPUSHED_COMMITS', source: 'git', message: `${CANARY} 2 unpushed commits` },
    { code: 'GIT_UNCOMMITTED_CHANGES', source: 'git', message: CANARY }, { code: 'NEW_FUTURE_CODE', source: 'x', message: CANARY }];
  const f = seq(json('jobDeletionPreview', { ...prev, jobId, deletable: false, protections }));
  del(f);
  expect(await screen.findByText(jobDeletionCopy.protections.UNPUSHED_COMMITS)).toBeTruthy();
  expect(screen.getByText(jobDeletionCopy.protections.GIT_UNCOMMITTED_CHANGES)).toBeTruthy();
  expect(screen.getAllByText(jobDeletionCopy.protectionFallback)).toHaveLength(1);
  expect(document.body.textContent).not.toMatch(/\d unpushed/);
  expect(screen.queryByRole('button', { name: jobDeletionCopy.deletePermanently })).toBeNull();
  noCanary();
});

it('network loss after DELETE is unconfirmed, clears the preview and does not resend', async () => {
  const f = seq(json('jobDeletionPreview', { ...prev, jobId }), netdown);
  const deleted = del(f);
  fireEvent.input(await screen.findByRole('textbox'), { target: { value: prev.displayFilename } });
  fireEvent.click(screen.getByRole('button', { name: jobDeletionCopy.deletePermanently }));
  expect(await screen.findByText(jobDeletionCopy.failed)).toBeTruthy();
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(deleted).not.toHaveBeenCalled();
  expect(f).toHaveBeenCalledTimes(2);
});


it('deployment changes clear the prior draft and server conflict context', async () => {
  const f = seq(fail(412, 'PRECONDITION_FAILED'), doc({ ...base, version: 'server_v2', label: 'Server A' }));
  const changed = vi.fn();
  const view = render(<JobOrganization job={base} client={createApiClient({ basePath: '/a', fetch: f })}
    basePath="/a" session={sessionA} onChanged={changed} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await screen.findByText(/Server A/);
  view.rerender(<JobOrganization job={base} client={createApiClient({ basePath: '/b', fetch: f })}
    basePath="/b" session={sessionA} onChanged={changed} />);
  await waitFor(() => expect(input().value).toBe(''));
  expect(document.body.textContent).not.toContain('Server A');
  expect(status()).toBe(''); expect(f).toHaveBeenCalledTimes(2);
});

it.each(['hidden', 'offline'] as const)('a sent save cancelled while %s becomes unconfirmed without replay on return', async reason => {
  let signal: AbortSignal | undefined;
  let release!: (r: Response) => void;
  const f = vi.fn<typeof fetch>().mockImplementation((_url, init) => new Promise((ok, no) => {
    signal = init?.signal ?? undefined; release = ok;
    signal?.addEventListener('abort', () => no(new DOMException('aborted', 'AbortError')));
  }));
  render(<Org fetcher={f} />);
  fireEvent.input(input(), { target: { value: 'Mine' } }); save();
  await waitFor(() => expect(f).toHaveBeenCalledOnce());
  if (reason === 'hidden') {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    await act(() => { document.dispatchEvent(new Event('visibilitychange')); });
  } else {
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
    await act(() => { window.dispatchEvent(new Event('offline')); });
  }
  await waitFor(() => expect(signal?.aborted).toBe(true));
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  await act(() => { document.dispatchEvent(new Event('visibilitychange')); window.dispatchEvent(new Event('online')); });
  await settled();
  expect(status()).toBe(copy.unconfirmed); expect(input().value).toBe('Mine');
  await act(async () => { release(doc({ ...base, version: 'late_v2', label: 'Mine' })()); await Promise.resolve(); });
  expect(status()).toBe(copy.unconfirmed); expect(f).toHaveBeenCalledOnce();
});

it.each(['running', 'completed'] as const)('the real Job route displays fixed %s deletion text after accepted DELETE', async state => {
  const bootstrap = { ...fx<Bootstrap>('bootstrap'), basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() };
  const auth = createBrowserSession({ bootstrap: () => Promise.resolve(bootstrap), exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  await auth.initialize({ kind: 'absent' });
  const f = seq(doc(base), json('jobDeletionPreview', { ...prev, jobId, version: v1 }), json('operation', op(state), 202));
  vi.stubGlobal('fetch', f);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: jobDeletionCopy.reviewDeletion }));
    fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: prev.displayFilename } });
    fireEvent.click(screen.getByRole('button', { name: jobDeletionCopy.deletePermanently }));
    await screen.findByText(jobCopy.thisJobWasDeleted);
    expect(screen.getByText(jobDeletionCopy.operationStates[state])).toBeTruthy();
    noCanary();
    expect(log(f)).toEqual([`GET /nested/api/v1/jobs/${jobId}`, `GET /nested/api/v1/jobs/${jobId}/deletion-preview`, `DELETE /nested/api/v1/jobs/${jobId}`]);
  } finally { auth.dispose(); vi.unstubAllGlobals(); }
});
