// #1896 (landed contract): the connection notice is a native <section> named by its own heading
// (aria-labelledby), with the named status only on the changing content, across offline, reconnect
// and coalesced events.
import axe from 'axe-core';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { appCopy as copy } from '../src/copy/shell';

let online = true;
let originalOnline: PropertyDescriptor | undefined;
beforeEach(() => {
  online = true;
  originalOnline = Object.getOwnPropertyDescriptor(navigator, 'onLine');
  Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
});
afterEach(() => {
  cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks();
  if (originalOnline) Object.defineProperty(navigator, 'onLine', originalOnline);
  else Reflect.deleteProperty(navigator, 'onLine');
});

function expectNoticeContract(heading: string, messages: string[]) {
  expect(document.querySelector('aside.connection-notice')).toBeNull();
  const notices = document.querySelectorAll('.connection-notice');
  expect(notices).toHaveLength(1);
  const section = notices[0] as HTMLElement;
  expect(section.tagName).toBe('SECTION');
  expect(section.hasAttribute('role'), 'section must keep its native region role').toBe(false);
  expect(section.hasAttribute('aria-label')).toBe(false);
  expect(screen.getByRole('region', { name: heading })).toBe(section);
  expect(screen.queryByRole('complementary', { name: copy.connectionStatus })).toBeNull();
  const statuses = screen.getAllByRole('status', { name: copy.connectionStatus });
  expect(statuses).toHaveLength(1);
  const status = statuses[0]!;
  expect(status.tagName).toBe('DIV');
  expect(section.contains(status) && status !== section).toBe(true);
  const h2 = within(status).getByRole('heading', { level: 2 });
  expect(h2.textContent).toBe(heading);
  expect(section.getAttribute('aria-labelledby')).toBe(h2.id);
  expect([...status.querySelectorAll('p')].map(p => p.textContent)).toEqual(messages);
  expect(within(status).queryAllByRole('button')).toHaveLength(0);
  expect(within(status).queryAllByRole('link')).toHaveLength(0);
}

async function axeViolations() {
  const root = document.querySelector('.connection-notice')!;
  const result = await axe.run(root, { runOnly: { type: 'rule', values: ['aria-allowed-role', 'aria-prohibited-attr'] }, resultTypes: ['violations'] });
  return result.violations.map(v => v.id);
}

const offline = [copy.browserReportsOffline, [copy.previouslyLoadedInformationMayBeOutOfDateReconnectAnd, copy.serverWorkMayContinueWhileThisPageIsDisconnected]] as const;
const reconnected = [copy.refreshLoadedInformation, [copy.theBrowserReportsAConnectionAgainPreviouslyLoadedInformationMay]] as const;

it('offline then reconnect keep a valid named status inside the heading-named section, with no side effects', async () => {
  const fetch = vi.fn(); const reload = vi.fn(); vi.stubGlobal('fetch', fetch);
  const store = vi.spyOn(Storage.prototype, 'setItem');
  render(<App reload={reload} />);
  expect(document.querySelector('.connection-notice')).toBeNull();
  const link = screen.getByRole('link', { name: 'Upload' }); link.focus();
  const address = window.location.href;
  online = false; fireEvent(window, new Event('offline'));
  expectNoticeContract(offline[0], [...offline[1]]);
  expect(await axeViolations()).toEqual([]);
  online = true; fireEvent(window, new Event('online'));
  expectNoticeContract(reconnected[0], [...reconnected[1]]);
  expect(await axeViolations()).toEqual([]);
  expect(document.activeElement).toBe(link);
  expect(window.location.href).toBe(address);
  expect(fetch).not.toHaveBeenCalled(); expect(reload).not.toHaveBeenCalled(); expect(store).not.toHaveBeenCalled();
});

it('coalesced offline/online events render one valid reconnect status', async () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  render(<App />);
  await act(() => {
    online = false; window.dispatchEvent(new Event('offline'));
    online = true; window.dispatchEvent(new Event('online'));
  });
  expectNoticeContract(reconnected[0], [...reconnected[1]]);
  expect(await axeViolations()).toEqual([]);
  expect(fetch).not.toHaveBeenCalled();
});

it('negative control: the former <aside role="status"> markup fails the contract and axe', async () => {
  online = false;
  render(<App />);
  // Reconstruct pre-#1896 <aside role="status"> markup from the real render.
  const section = document.querySelector('.connection-notice')!;
  const aside = document.createElement('aside');
  aside.className = section.className;
  aside.setAttribute('role', 'status'); aside.setAttribute('aria-label', copy.connectionStatus);
  const inner = section.querySelector('div[role="status"]')!;
  while (inner.firstChild) aside.appendChild(inner.firstChild);
  section.replaceWith(aside);
  expect(() => expectNoticeContract(offline[0], [...offline[1]])).toThrow();
  expect(await axeViolations()).toContain('aria-allowed-role');
});
