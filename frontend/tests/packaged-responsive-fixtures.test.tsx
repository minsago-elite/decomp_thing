import { createHash, webcrypto } from 'node:crypto';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/preact';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
// The packaged driver is an untyped Node module run by CI as-is; its shape is declared below and asserted by use.
// @ts-expect-error -- no declaration file for the .mjs driver
import * as untypedDriver from '../../scripts/packaged-browser-responsive.mjs';

// #619 packaged responsive driver control. The real App, routes, components and API client render the generator's
// `responsive` scenario through the driver's own fixture responder, and the driver's selector expressions are
// evaluated against that DOM. jsdom has no layout: this checks labels, structure, product copy and exact content
// only. Widths, overflow, scrolling, focus-visible and trusted input remain hosted-browser evidence.
type Respond = { status: number; document?: unknown; bytes?: Buffer; contentType?: string; headers?: Record<string, string>; artifact?: { servedSha256: string } };
type Fixtures = {
  identity: { longName: string; hex: { rows: number; textSha256: string; chunkPath: string }; artifactPaths: Record<string, string> };
  tamper: { path: string | null };
  respond: (method: string, path: string, accept?: string) => Respond;
};
type Driver = {
  responsiveFixtures: (options: { repo: string; python: string; buildId: string; basePath: string }) => Fixtures;
  RESPONSIVE_REGIONS: readonly { key: string; path: string; steps: string[]; region: string; mode: string; bytePreview?: boolean; hexRows?: boolean; artifact?: string }[];
  PRODUCT_COPY: { caseRefusal: string; previewTitles: readonly string[] };
  PREFERENCES: { trigger: string; panel: string };
  regionExpr: (name: string) => string;
  byLabel: (prefix: string) => string;
  summaryExpr: (sel: string) => string;
  bytePreviewExpr: (sel: string) => string;
  hexRowsExpr: (sel: string) => string;
  FOCUS: string;
};

const repo = resolve(process.cwd(), '..');
let driver: Driver;
let fixtures: Fixtures;
const reads: { path: string; status: number }[] = [];
const sessions: ReturnType<typeof createBrowserSession>[] = [];
const run = <T,>(expr: string): T => (0, eval)(expr) as T;

beforeAll(() => {
  driver = untypedDriver as Driver;
  fixtures = driver.responsiveFixtures({ repo, python: 'python3', buildId: 'b'.repeat(64), basePath: '/nested/' });
}, 60_000);

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  reads.length = 0; fixtures.tamper.path = null;
  // jsdom lacks Element.checkVisibility; this stand-in covers only [hidden] and closed-<details> content. It never
  // decides layout and is not browser evidence.
  if (!('checkVisibility' in Element.prototype)) {
    const visibleInJsdom = (element: Element) => {
      for (let e: Element | null = element; e; e = e.parentElement) {
        if (e.hasAttribute('hidden')) return false;
        const parent = e.parentElement;
        if (parent instanceof HTMLDetailsElement && !parent.open && e.tagName !== 'SUMMARY') return false;
      }
      return true;
    };
    Object.defineProperty(Element.prototype, 'checkVisibility', { configurable: true, value(this: Element) { return visibleInJsdom(this); } });
  }
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://127.0.0.1');
    const accept = new Headers(init?.headers).get('Accept') ?? '';
    const response = fixtures.respond(init?.method ?? 'GET', url.pathname + url.search, accept);
    reads.push({ path: url.pathname + url.search, status: response.status });
    const body = response.bytes ? new Uint8Array(response.bytes) : JSON.stringify(response.document);
    return Promise.resolve(new Response(body, { status: response.status, headers: { 'Content-Type': response.contentType ?? 'application/json; charset=utf-8',
      'X-Request-ID': (response.document as { requestId?: string } | undefined)?.requestId ?? 'request_responsive_artifact', ...response.headers } }));
  }));
});
afterEach(() => { cleanup(); for (const session of sessions.splice(0)) session.dispose(); fixtures.tamper.path = null; });

async function mount(path: string) {
  const bootstrap = (fixtures.respond('GET', '/nested/api/v1/bootstrap').document as { data: Bootstrap }).data;
  const session = createBrowserSession({ bootstrap: () => Promise.resolve(bootstrap), exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  sessions.push(session); await session.initialize({ kind: 'absent' });
  history.replaceState(null, '', path);
  const view = render(<App basePath="/nested" session={session} />);
  await waitFor(() => expect(document.querySelector('main h1')).not.toBeNull(), { timeout: 10_000 });
  return view;
}
async function step(prefix: string) {
  const button = await waitFor(() => { const found = run<HTMLButtonElement | undefined>(driver.byLabel(prefix)); expect(found).toBeTruthy(); return found!; }, { timeout: 10_000 });
  await act(() => { fireEvent.click(button); });
}
const region = (key: string) => driver.RESPONSIVE_REGIONS.find(value => value.key === key)!;
async function openRegion(key: string) {
  const r = region(key);
  await mount(r.path);
  for (const label of r.steps) await step(label);
  return waitFor(() => { const found = run<HTMLElement | undefined>(driver.regionExpr(r.region)); expect(found).toBeTruthy(); return found!; }, { timeout: 10_000 });
}
const failed = () => reads.filter(value => value.status >= 400);

it.each(['exploration-partial', 'exploration-preparation'])('%s: the driver reaches the real named region with one exact artifact read', async key => {
  const element = await openRegion(key);
  expect(element.getAttribute('aria-label')).toBe('Retained candidate records');
  expect(/[֐-ۿ]/u.test(element.textContent ?? '')).toBe(true);
  const artifact = fixtures.identity.artifactPaths[region(key).artifact!]!;
  expect(reads.filter(value => value.path === artifact)).toHaveLength(1);
  expect(failed()).toEqual([]);
});

it('digest control: one altered artifact byte yields only the product case-refusal copy; the exact bytes render', async () => {
  const r = region('exploration-partial');
  const artifact = fixtures.identity.artifactPaths.partial!;
  fixtures.tamper.path = artifact;
  await mount(r.path);
  for (const label of r.steps) await step(label);
  const alerts = await waitFor(() => { const found = [...document.querySelectorAll('main [role="alert"]')].map(e => e.textContent?.trim()); expect(found.length).toBeGreaterThan(0); return found; }, { timeout: 10_000 });
  expect(alerts).toEqual([driver.PRODUCT_COPY.caseRefusal]);
  expect(run(`!!${driver.regionExpr(r.region)}`)).toBe(false);
  expect(reads.filter(value => value.path === artifact)).toHaveLength(1);
  expect(failed()).toEqual([]);
});

it('validation byte previews start closed; the driver summary selector opens real previews in the region', async () => {
  const r = region('validation-bytes');
  const element = await openRegion('validation-bytes');
  const sel = driver.regionExpr(r.region);
  const before = run<{ open: boolean; total: number; visible: number; summary: string }>(driver.bytePreviewExpr(sel));
  expect(before.open).toBe(false);
  expect(before.total).toBeGreaterThan(0);
  expect(before.visible).toBe(0);
  expect(driver.PRODUCT_COPY.previewTitles).toContain(before.summary);
  const summary = run<HTMLElement>(driver.summaryExpr(sel));
  expect(element.contains(summary)).toBe(true);
  await act(() => { fireEvent.click(summary); });
  const after = run<{ open: boolean; visible: number }>(driver.bytePreviewExpr(sel));
  expect(after.open).toBe(true);
  expect(after.visible).toBeGreaterThan(0);
  expect(failed()).toEqual([]);
});

it('source hex: every requested row from the exact chunk renders in the reflow region', async () => {
  const r = region('source-hex');
  expect(r.mode).toBe('reflow');
  await openRegion('source-hex');
  const rows = run<{ rows: number; text: string }>(driver.hexRowsExpr(driver.regionExpr(r.region)));
  expect(rows.rows).toBe(fixtures.identity.hex.rows);
  expect(createHash('sha256').update(rows.text, 'utf8').digest('hex')).toBe(fixtures.identity.hex.textSha256);
  expect(reads.filter(value => value.path === fixtures.identity.hex.chunkPath)).toHaveLength(1);
  expect(failed()).toEqual([]);
});

it('display preferences is a disclosure: the driver trigger opens its panel and Escape returns focus', async () => {
  await mount('/nested/jobs/f619f619f619f619f619f619f619f619');
  await waitFor(() => expect(document.body.textContent).toContain(fixtures.identity.longName), { timeout: 10_000 });
  const trigger = document.querySelector<HTMLButtonElement>(driver.PREFERENCES.trigger)!;
  const panel = document.getElementById(driver.PREFERENCES.panel)!;
  expect(panel.getAttribute('role')).toBeNull();
  expect(panel.hidden).toBe(true);
  await act(() => { trigger.focus(); fireEvent.click(trigger); });
  expect(trigger.getAttribute('aria-expanded')).toBe('true');
  expect(panel.hidden).toBe(false);
  panel.querySelector('select')!.focus();
  expect(run<{ inPreferences: boolean }>(driver.FOCUS).inPreferences).toBe(true);
  await act(() => { fireEvent.keyDown(document.activeElement!, { key: 'Escape' }); });
  expect(trigger.getAttribute('aria-expanded')).toBe('false');
  expect(run<{ trigger: boolean }>(driver.FOCUS).trigger).toBe(true);
  expect(failed()).toEqual([]);
});
