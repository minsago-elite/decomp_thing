import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { ViewBoundary } from '../src/shared/ViewBoundary';
import { createAssetRecovery } from '../src/app/assetRecovery';

const fixtureMarker = 'DECOMP_TEST_ONLY_SENTINEL';

function navigationMedia(initial: boolean) {
  let narrow = initial;
  const listeners = new Set<() => void>();
  const media = {
    get matches() { return narrow; },
    addEventListener: vi.fn((type: string, listener: () => void) => { if (type === 'change') listeners.add(listener); }),
    removeEventListener: vi.fn((type: string, listener: () => void) => { if (type === 'change') listeners.delete(listener); }),
  };
  vi.stubGlobal('matchMedia', vi.fn((query: string) => {
    expect(query).toBe('(width < 48rem)');
    return media;
  }));
  return {
    media,
    listeners: () => listeners.size,
    change: async (value: boolean) => {
      await act(() => {
        narrow = value;
        for (const listener of listeners) listener();
      });
    },
  };
}

describe('public workbench shell', () => {
  it('exposes navigation and truthful availability without contacting APIs', () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    render(<App />);
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeTruthy();
    expect(screen.getByRole('main')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Skip to content' }).getAttribute('href')).toBe('#main');
    expect(screen.getByRole('heading', { level: 1, name: 'Your work, with its evidence' })).toBeTruthy();
    expect(screen.getByText(/does not read jobs or start workflows/)).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
    expect(document.title).toBe('Jobs · Decomp Workbench');
    expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1 }));
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    skip.focus();
    fireEvent.click(skip);
    expect(document.activeElement).toBe(screen.getByRole('main'));
  });

  it('loads the split runtime route and returns with browser history', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(window.location.pathname).toBe('/runtime');
    expect(document.title).toBe('Runtime status · Decomp Workbench');
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1, name: 'Runtime status' })));
    window.history.back();
    expect(await screen.findByRole('heading', { level: 1, name: 'Your work, with its evidence' })).toBeTruthy();
    expect(window.location.pathname).toBe('/');
    expect(document.title).toBe('Jobs · Decomp Workbench');
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1, name: 'Your work, with its evidence' })));
  });

  it('preserves the deployment prefix for direct routes and navigation', async () => {
    window.history.replaceState(null, '', '/tools/decomp/runtime?from=bookmark');
    render(<App basePath="/tools/decomp" />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Workspace' }).getAttribute('href')).toBe('/tools/decomp/');
    expect(window.location.search).toBe('?from=bookmark');
    fireEvent.click(screen.getByRole('link', { name: 'Workspace' }));
    expect(await screen.findByRole('heading', { name: 'Your work, with its evidence' })).toBeTruthy();
    expect(window.location.pathname).toBe('/tools/decomp/');
  });

  it('restores the dedicated upload route through navigation and history without starting work', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/tools/decomp/upload');
    render(<App basePath="/tools/decomp" />);
    expect(screen.getByRole('heading', { level: 1, name: 'Upload a binary' })).toBeTruthy();
    expect(document.title).toBe('Upload a binary · Decomp Workbench');
    expect(screen.getByRole('navigation', { name: 'Breadcrumbs' }).textContent).toContain('All jobs');
    expect(screen.getByRole('link', { name: 'Upload' }).getAttribute('aria-current')).toBe('page');
    fireEvent.click(screen.getByRole('link', { name: 'All jobs' }));
    expect(await screen.findByRole('heading', { name: 'Your work, with its evidence' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Workspace' }).getAttribute('aria-current')).toBe('page');
    window.history.back();
    expect(await screen.findByRole('heading', { level: 1, name: 'Upload a binary' })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1, name: 'Upload a binary' })));
    expect(fetch).not.toHaveBeenCalled();
  });

  it('preserves keyboard focus across query-only history and background shell updates', async () => {
    const view = render(<App />);
    const navigation = screen.getByRole('link', { name: 'Upload' });
    navigation.focus();
    await act(() => {
      window.history.pushState(null, '', '/?filter=recent');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(document.activeElement).toBe(navigation);
    view.rerender(<App />);
    expect(document.activeElement).toBe(navigation);
    await act(() => {
      window.history.replaceState(null, '', '/');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(document.activeElement).toBe(navigation);
  });

  it('keeps a version notice in view when focusing the next route', async () => {
    const recovery = createAssetRecovery();
    recovery.reportFailure();
    const focus = vi.spyOn(HTMLElement.prototype, 'focus');
    try {
      render(<App recovery={recovery} />);
      fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
      const heading = await screen.findByRole('heading', { name: 'Runtime status' });
      await waitFor(() => expect(document.activeElement).toBe(heading));
      expect(focus).toHaveBeenCalledWith({ preventScroll: true });
      expect(screen.getByRole('heading', { name: 'The application may have updated' })).toBeTruthy();
    } finally {
      focus.mockRestore();
    }
  });

  it('gives unknown routes a clear return destination', () => {
    window.history.replaceState(null, '', '/missing.view');
    render(<App />);
    expect(screen.getByRole('heading', { name: 'This page could not be found' })).toBeTruthy();
    expect(document.title).toBe('Page unavailable · Decomp Workbench');
    expect(screen.getByRole('link', { name: 'Return to the workspace' }).getAttribute('href')).toBe('/');
  });
});

describe('responsive workbench navigation', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('keeps the desktop sidebar links available and the disclosure button hidden', () => {
    navigationMedia(false);
    render(<App />);
    expect(screen.getByRole('link', { name: 'Workspace' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByRole('link', { name: 'Upload' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Runtime status' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Navigation' })).toBeNull();
    expect(document.querySelector<HTMLButtonElement>('.navigation-toggle')?.hidden).toBe(true);
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(false);
  });

  it('opens labelled narrow navigation and closes it after a real route change without work or storage writes', async () => {
    navigationMedia(true);
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    render(<App />);
    const toggle = screen.getByRole('button', { name: 'Navigation' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.getElementById(toggle.getAttribute('aria-controls')!)?.hidden).toBe(true);
    expect(screen.queryByRole('link', { name: 'Runtime status' })).toBeNull();
    fireEvent.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    const heading = await screen.findByRole('heading', { level: 1, name: 'Runtime status' });
    await waitFor(() => expect(document.activeElement).toBe(heading));
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(true);
    expect(window.location.pathname).toBe('/runtime');
    expect(fetch).not.toHaveBeenCalled();
    expect(writes).not.toHaveBeenCalled();
  });

  it('closes narrow navigation on Escape and returns focus without navigating', () => {
    navigationMedia(true);
    render(<App />);
    const toggle = screen.getByRole('button', { name: 'Navigation' });
    fireEvent.click(toggle);
    const upload = screen.getByRole('link', { name: 'Upload' });
    upload.focus();
    const address = window.location.href;
    fireEvent.keyDown(upload, { key: 'Escape' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(true);
    expect(document.activeElement).toBe(toggle);
    expect(window.location.href).toBe(address);
  });

  it('keeps focus on visible navigation when the live breakpoint changes in either direction', async () => {
    const media = navigationMedia(false);
    render(<App />);
    screen.getByRole('link', { name: 'Upload' }).focus();
    await media.change(true);
    const toggle = screen.getByRole('button', { name: 'Navigation' });
    expect(document.activeElement).toBe(toggle);
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(true);
    await media.change(false);
    expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Workspace' }));
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(false);
    expect(screen.queryByRole('button', { name: 'Navigation' })).toBeNull();
  });

  it('returns focus to the disclosure when its current route is selected again', () => {
    navigationMedia(true);
    render(<App />);
    const toggle = screen.getByRole('button', { name: 'Navigation' });
    fireEvent.click(toggle);
    const workspace = screen.getByRole('link', { name: 'Workspace' });
    workspace.focus();
    fireEvent.click(workspace);
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(toggle);
    expect(window.location.pathname).toBe('/');
  });

  it('preserves an open disclosure and focus during query-only history and background updates', async () => {
    navigationMedia(true);
    const view = render(<App />);
    const toggle = screen.getByRole('button', { name: 'Navigation' });
    fireEvent.click(toggle);
    const upload = screen.getByRole('link', { name: 'Upload' });
    upload.focus();
    await act(() => {
      window.history.pushState(null, '', '/?filter=recent');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    view.rerender(<App />);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(document.activeElement).toBe(upload);
    expect(document.getElementById('main-navigation-links')?.hidden).toBe(false);
  });

  it('removes the owned breakpoint listener and starts a remounted shell closed', () => {
    const media = navigationMedia(true);
    const first = render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Navigation' }));
    expect(media.listeners()).toBe(1);
    const registration = media.media.addEventListener.mock.calls[0]!;
    first.unmount();
    expect(media.media.removeEventListener).toHaveBeenCalledWith(...registration);
    expect(media.listeners()).toBe(0);
    const second = render(<App />);
    expect(screen.getByRole('button', { name: 'Navigation' }).getAttribute('aria-expanded')).toBe('false');
    expect(media.listeners()).toBe(1);
    second.unmount();
    expect(media.listeners()).toBe(0);
  });
});

describe('browser offline notices', () => {
  let online = true;
  let originalOnline: PropertyDescriptor | undefined;
  beforeEach(() => {
    online = true;
    originalOnline = Object.getOwnPropertyDescriptor(navigator, 'onLine');
    Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
  });
  afterEach(() => {
    if (originalOnline) Object.defineProperty(navigator, 'onLine', originalOnline);
    else Reflect.deleteProperty(navigator, 'onLine');
  });

  it('marks offline information without changing focus navigation storage or requests', () => {
    const fetch = vi.fn(); const reload = vi.fn();
    const store = vi.spyOn(Storage.prototype, 'setItem');
    vi.stubGlobal('fetch', fetch);
    try {
      render(<App reload={reload} />);
      expect(screen.queryByRole('status', { name: 'Connection status' })).toBeNull();
      const navigation = screen.getByRole('link', { name: 'Upload' });
      navigation.focus();
      const address = window.location.href;
      online = false;
      fireEvent(window, new Event('offline'));
      const notice = screen.getByRole('status', { name: 'Connection status' });
      expect(notice.textContent).toContain('Browser reports offline');
      expect(notice.textContent).toContain('Previously loaded information may be out of date.');
      expect(notice.textContent).toContain('Server work may continue');
      expect(document.activeElement).toBe(navigation);
      expect(window.location.href).toBe(address);
      expect(fetch).not.toHaveBeenCalled();
      expect(reload).not.toHaveBeenCalled();
      expect(store).not.toHaveBeenCalled();
    } finally { store.mockRestore(); }
  });

  it('keeps the loaded-information warning after reconnect without automatically refreshing', () => {
    online = false;
    const fetch = vi.fn(); const reload = vi.fn();
    vi.stubGlobal('fetch', fetch);
    render(<App reload={reload} />);
    expect(screen.getByRole('status', { name: 'Connection status' }).textContent).toContain('Browser reports offline');
    online = true;
    fireEvent(window, new Event('online'));
    const notice = screen.getByRole('status', { name: 'Connection status' });
    expect(notice.textContent).toContain('Refresh loaded information');
    expect(notice.textContent).toContain('Previously loaded information may still be out of date.');
    expect(notice.textContent).not.toContain('Browser reports offline');
    expect(fetch).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it('retains a brief offline hint when both browser events share one render', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    render(<App />);
    fireEvent(window, new Event('online'));
    expect(screen.queryByRole('status', { name: 'Connection status' })).toBeNull();
    await act(() => {
      online = false;
      window.dispatchEvent(new Event('offline'));
      online = true;
      window.dispatchEvent(new Event('online'));
    });
    expect(screen.getAllByRole('status', { name: 'Connection status' })).toHaveLength(1);
    expect(screen.getByRole('status', { name: 'Connection status' }).textContent).toContain('Previously loaded information may still be out of date.');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('removes hint listeners and keeps the warning within its shell instance', () => {
    const added = vi.spyOn(window, 'addEventListener');
    const removed = vi.spyOn(window, 'removeEventListener');
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    try {
      const first = render(<App />);
      online = false;
      fireEvent(window, new Event('offline'));
      expect(screen.getByRole('status', { name: 'Connection status' })).toBeTruthy();
      const hints = added.mock.calls.filter(([type]) => type === 'online' || type === 'offline');
      expect(hints).toHaveLength(2);
      first.unmount();
      for (const [type, listener] of hints) expect(removed).toHaveBeenCalledWith(type, listener);
      online = true;
      const second = render(<App />);
      expect(screen.queryByRole('status', { name: 'Connection status' })).toBeNull();
      expect(fetch).not.toHaveBeenCalled();
      second.unmount();
    } finally { added.mockRestore(); removed.mockRestore(); }
  });
});

describe('view errors', () => {
  it('contains private exception details and retries only the view', async () => {
    let fails = true;
    function FailingView() {
      if (fails) throw new Error(fixtureMarker);
      return <p>View restored</p>;
    }
    render(<ViewBoundary><FailingView /></ViewBoundary>);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByText(fixtureMarker)).toBeNull();
    fails = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('View restored')).toBeTruthy();
  });
});
