// #1896 packaged-helper contract against the real App: the packaged driver's own DOM probe and axe
// expression (scripts/packaged-browser-connection-notice.mjs) run on the real signed-out shell with the
// real useBrowserAvailability hook and a mocked session gateway. jsdom events here are test-only; real
// Chrome trust/onLine/AX evidence comes only from the packaged run.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import axe from 'axe-core';
import { act, cleanup, fireEvent, render } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
// @ts-expect-error untyped repository helper; typed locally below
import * as untypedHelper from '../../scripts/packaged-browser-connection-notice.mjs';

type Helper = {
  connectionDomProbe: () => unknown; axeExpression: () => string; assessConnectionDom: (d: unknown, s: string) => string[];
  assessConnectionAxe: (a: unknown) => string[]; AXE_RULES: string[]; AXE_VERSION: string; REVALIDATION_MAX_MS: number; HOME: { h1: string };
};
const helper = untypedHelper as unknown as Helper;
const axeSha256 = 'f'.repeat(64);

let online = true;
let original: PropertyDescriptor | undefined;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => {
  online = true;
  original = Object.getOwnPropertyDescriptor(navigator, 'onLine');
  Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
  (globalThis as unknown as { axe: typeof axe }).axe = axe;
});
afterEach(() => {
  cleanup(); for (const s of sessions.splice(0)) s.dispose(); vi.restoreAllMocks();
  if (original) Object.defineProperty(navigator, 'onLine', original); else Reflect.deleteProperty(navigator, 'onLine');
});

async function settle() { for (let i = 0; i < 4; i++) await act(async () => { await new Promise(r => setTimeout(r, 0)); }); }
const probe = () => JSON.parse(JSON.stringify(helper.connectionDomProbe())) as { asideCount: number };
async function runAxe() {
  const result = await (0, eval)(helper.axeExpression()) as object;
  return { ...result, rules: helper.AXE_RULES, sha256: axeSha256 };
}

async function signedOutHome() {
  const gateway = { bootstrap: vi.fn(() => Promise.reject(new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_REQUIRED' }))), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/'); sessions.push(session);
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  const store = vi.spyOn(Storage.prototype, 'setItem');
  render(<App session={session} />);
  void session.refresh();
  await settle();
  await vi.waitFor(() => expect(document.querySelector('main h1')?.textContent).toBe(helper.HOME.h1));
  expect(session.snapshot()).toMatchObject({ status: 'required' });
  return { gateway, session, fetch, store };
}

it('real signed-out App satisfies the packaged DOM and axe contract offline and after reconnect, with no revalidation', async () => {
  const { gateway, fetch, store } = await signedOutHome();
  expect(probe().asideCount).toBe(0);
  const calls = gateway.bootstrap.mock.calls.length;
  const href = location.href;
  const link = document.querySelector<HTMLElement>('a[href="/upload"]') ?? document.querySelector<HTMLElement>('nav a')!;
  link.focus();
  online = false; fireEvent(window, new Event('offline'));
  expect(helper.assessConnectionDom(probe(), 'offline')).toEqual([]);
  expect(helper.assessConnectionAxe(await runAxe())).toEqual([]);
  online = true; fireEvent(window, new Event('online'));
  expect(helper.assessConnectionDom(probe(), 'reconnected')).toEqual([]);
  expect(helper.assessConnectionAxe(await runAxe())).toEqual([]);
  // Wait past the 250 + random*1000 ms timer: signed-out revalidate must remain a no-op.
  await act(async () => { await new Promise(r => setTimeout(r, helper.REVALIDATION_MAX_MS + 250)); });
  expect(gateway.bootstrap.mock.calls.length).toBe(calls);
  expect(gateway.logout).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled(); expect(store).not.toHaveBeenCalled();
  expect(document.activeElement).toBe(link); expect(location.href).toBe(href);
  const version = (await runAxe() as { version?: string }).version;
  expect(version).toBe(helper.AXE_VERSION);
  expect(readFileSync(resolve(process.cwd(), 'node_modules/axe-core/package.json'), 'utf8')).toContain(`"version": "${helper.AXE_VERSION}"`);
}, 10_000);

it('negative control: the former aside[role=status] rebuilt from the real render fails the packaged DOM and axe gate', async () => {
  await signedOutHome();
  online = false; fireEvent(window, new Event('offline'));
  const aside = document.querySelector('aside.connection-notice')!;
  const inner = aside.querySelector('div[role="status"]')!;
  inner.removeAttribute('role'); inner.removeAttribute('aria-label');
  aside.setAttribute('role', 'status');
  const dom = helper.assessConnectionDom(probe(), 'offline');
  expect(dom.some(f => /native aside/.test(f))).toBe(true);
  expect(dom.some(f => /status must be one labelled inner div/.test(f))).toBe(true);
  expect(helper.assessConnectionAxe(await runAxe()).some(f => /aria-allowed-role/.test(f))).toBe(true);
});
