import { cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { DISPLAY_PREFERENCES_KEY, DisplayPreferences, readDisplayPreferences, resetDisplayPreferences, writeDisplayPreferences } from '../src/app/DisplayPreferences';
import type { DisplayPreferenceValues } from '../src/app/DisplayPreferences';

const privateMarker = 'PRIVATE_DISPLAY_STORAGE_SENTINEL';
const system = { theme: 'system', motion: 'system' };

function memoryStorage(initial: Record<string, string> = {}) {
  const records = new Map(Object.entries(initial));
  const storage = {
    getItem: vi.fn((key: string) => records.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => { records.set(key, value); }),
    removeItem: vi.fn((key: string) => { records.delete(key); }),
  };
  return { records, storage };
}

beforeEach(() => {
  window.localStorage.removeItem(DISPLAY_PREFERENCES_KEY);
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-motion');
});

afterEach(() => {
  cleanup();
  window.localStorage.removeItem(DISPLAY_PREFERENCES_KEY);
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-motion');
  vi.restoreAllMocks();
});

describe('bounded display-only storage', () => {
  it('defaults to system and reads every supported theme and motion combination', () => {
    const { records, storage } = memoryStorage();
    expect(readDisplayPreferences(() => storage)).toEqual(system);
    for (const theme of ['system', 'light', 'dark']) {
      for (const motion of ['system', 'reduce']) {
        records.set(DISPLAY_PREFERENCES_KEY, JSON.stringify({ version: 1, theme, motion }));
        expect(readDisplayPreferences(() => storage)).toEqual({ theme, motion });
      }
    }
    expect(storage.getItem.mock.calls.every(([key]) => key === DISPLAY_PREFERENCES_KEY)).toBe(true);
    expect(storage.setItem).not.toHaveBeenCalled();
  });

  it('refuses malformed oversized unknown-version or private-field records without rewriting them', () => {
    const rawValues = [
      '{', 'null', '[]', '1', JSON.stringify('dark'),
      JSON.stringify({ version: 2, ...system }),
      JSON.stringify({ version: 1, theme: 'unknown', motion: 'system' }),
      JSON.stringify({ version: 1, theme: 'system', motion: 'full' }),
      JSON.stringify({ version: 1, theme: 'dark' }),
      JSON.stringify({ version: 1, ...system, session: privateMarker }),
      JSON.stringify({ version: 1, ...system, extra: 'x'.repeat(1000) }),
    ];
    for (const raw of rawValues) {
      const { records, storage } = memoryStorage({ [DISPLAY_PREFERENCES_KEY]: raw, unrelated: privateMarker });
      expect(readDisplayPreferences(() => storage)).toEqual(system);
      expect(records.get(DISPLAY_PREFERENCES_KEY)).toBe(raw);
      expect(records.get('unrelated')).toBe(privateMarker);
      expect(storage.setItem).not.toHaveBeenCalled();
      expect(storage.removeItem).not.toHaveBeenCalled();
    }
  });

  it('persists only version and admitted display enums even when the caller has additional private data', () => {
    const { records, storage } = memoryStorage({ unrelated: privateMarker });
    const supplied = { theme: 'dark' as const, motion: 'reduce' as const, session: privateMarker, job: privateMarker };
    expect(writeDisplayPreferences(supplied, () => storage)).toBe(true);
    expect(records.get(DISPLAY_PREFERENCES_KEY)).toBe('{"version":1,"theme":"dark","motion":"reduce"}');
    expect(records.get('unrelated')).toBe(privateMarker);
    expect(storage.setItem).toHaveBeenCalledTimes(1);
    let reads = 0;
    const changing = { get theme() { return ++reads === 1 ? 'light' : privateMarker; }, motion: 'system' };
    expect(writeDisplayPreferences(changing as unknown as DisplayPreferenceValues, () => storage)).toBe(true);
    expect(reads).toBe(1);
    expect(records.get(DISPLAY_PREFERENCES_KEY)).toBe('{"version":1,"theme":"light","motion":"system"}');
  });

  it('rejects invalid values before a storage write', () => {
    const { storage } = memoryStorage();
    for (const values of [{ theme: privateMarker, motion: 'system' }, { theme: 'light', motion: 'full' }]) {
      expect(writeDisplayPreferences(values as unknown as DisplayPreferenceValues, () => storage)).toBe(false);
    }
    expect(storage.setItem).not.toHaveBeenCalled();
  });

  it('recovers from inaccessible storage and detects ignored writes and removals', () => {
    const denied = () => { throw new Error(privateMarker); };
    expect(readDisplayPreferences(denied)).toEqual(system);
    expect(writeDisplayPreferences({ theme: 'dark', motion: 'reduce' }, denied)).toBe(false);
    expect(resetDisplayPreferences(denied)).toBe(false);
    const { records, storage } = memoryStorage();
    storage.setItem.mockImplementation(() => {});
    expect(writeDisplayPreferences({ theme: 'dark', motion: 'reduce' }, () => storage)).toBe(false);
    records.set(DISPLAY_PREFERENCES_KEY, '{"version":1,"theme":"dark","motion":"reduce"}');
    storage.removeItem.mockImplementation(() => {});
    expect(resetDisplayPreferences(() => storage)).toBe(false);
  });

  it('resets only its dedicated preference slot', () => {
    const { records, storage } = memoryStorage({ [DISPLAY_PREFERENCES_KEY]: privateMarker, unrelated: privateMarker });
    expect(resetDisplayPreferences(() => storage)).toBe(true);
    expect(resetDisplayPreferences(() => storage)).toBe(true);
    expect(records.has(DISPLAY_PREFERENCES_KEY)).toBe(false);
    expect(records.get('unrelated')).toBe(privateMarker);
    expect(readDisplayPreferences(() => storage)).toEqual(system);
  });
});

describe('display preferences before the shell mounts', () => {
  async function loadBootstrap() {
    vi.resetModules();
    await import('../src/app/display-preferences-bootstrap.js');
  }

  it('applies every saved display choice before mounting the actual shell without startup writes', async () => {
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    const removes = vi.spyOn(Storage.prototype, 'removeItem');
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    for (const theme of ['system', 'light', 'dark']) {
      for (const motion of ['system', 'reduce']) {
        const raw = JSON.stringify({ version: 1, theme, motion });
        window.localStorage.setItem(DISPLAY_PREFERENCES_KEY, raw);
        writes.mockClear(); removes.mockClear();
        await loadBootstrap();
        expect(document.documentElement.getAttribute('data-theme')).toBe(theme);
        expect(document.documentElement.getAttribute('data-motion')).toBe(motion);
        const view = render(<App />);
        expect(document.documentElement.getAttribute('data-theme')).toBe(theme);
        expect(document.documentElement.getAttribute('data-motion')).toBe(motion);
        expect(writes).not.toHaveBeenCalled();
        expect(removes).not.toHaveBeenCalled();
        expect(window.localStorage.getItem(DISPLAY_PREFERENCES_KEY)).toBe(raw);
        expect(fetch).not.toHaveBeenCalled();
        view.unmount();
      }
    }
  });

  it('uses the same strict bounded record contract as the shell without rewriting rejected data', async () => {
    const rawValues = ['{', 'null', '[]', '1', JSON.stringify('dark'),
      JSON.stringify({ version: 2, ...system }),
      JSON.stringify({ version: 1, theme: 'unknown', motion: 'system' }),
      JSON.stringify({ version: 1, theme: 'light', motion: 'full' }),
      JSON.stringify({ version: 1, theme: 'dark' }),
      JSON.stringify({ version: 1, ...system, session: privateMarker }),
      JSON.stringify({ version: 1, ...system, extra: 'x'.repeat(1000) })];
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    const removes = vi.spyOn(Storage.prototype, 'removeItem');
    for (const raw of rawValues) {
      window.localStorage.setItem(DISPLAY_PREFERENCES_KEY, raw);
      writes.mockClear(); removes.mockClear();
      await loadBootstrap();
      expect(document.documentElement.getAttribute('data-theme')).toBe(readDisplayPreferences().theme);
      expect(document.documentElement.getAttribute('data-motion')).toBe(readDisplayPreferences().motion);
      expect(document.documentElement.getAttribute('data-theme')).toBe('system');
      expect(document.documentElement.getAttribute('data-motion')).toBe('system');
      expect(window.localStorage.getItem(DISPLAY_PREFERENCES_KEY)).toBe(raw);
      expect(writes).not.toHaveBeenCalled();
      expect(removes).not.toHaveBeenCalled();
    }
  });

  it('applies system settings when startup storage is denied without leaking or writing anything', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error(privateMarker); });
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    const removes = vi.spyOn(Storage.prototype, 'removeItem');
    const errors = vi.spyOn(console, 'error');
    await loadBootstrap();
    expect(document.documentElement.getAttribute('data-theme')).toBe('system');
    expect(document.documentElement.getAttribute('data-motion')).toBe('system');
    expect(writes).not.toHaveBeenCalled();
    expect(removes).not.toHaveBeenCalled();
    expect(errors).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain(privateMarker);
  });
});

describe('workbench display controls', () => {
  it('mounts the actual public shell with system preferences without writes or API requests', () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    render(<App />);
    expect(screen.getByRole('button', { name: 'Display preferences' }).getAttribute('aria-expanded')).toBe('false');
    expect(document.documentElement.getAttribute('data-theme')).toBe('system');
    expect(document.documentElement.getAttribute('data-motion')).toBe('system');
    expect(writes).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('applies light dark and system selections and saves only the selected display values', () => {
    const { records, storage } = memoryStorage();
    render(<DisplayPreferences storage={() => storage} />);
    fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
    const select = screen.getByLabelText<HTMLSelectElement>('Theme');
    for (const theme of ['light', 'dark', 'system']) {
      fireEvent.change(select, { target: { value: theme } });
      expect(select.value).toBe(theme);
      expect(document.documentElement.getAttribute('data-theme')).toBe(theme);
      expect(records.get(DISPLAY_PREFERENCES_KEY)).toBe(JSON.stringify({ version: 1, theme, motion: 'system' }));
    }
    expect(screen.getByRole('status').textContent).toBe('Display preferences saved in this browser.');
  });

  it('keeps reduced motion on by choice and restores system settings with an explicit reset', () => {
    const { records, storage } = memoryStorage({ unrelated: privateMarker });
    render(<DisplayPreferences storage={() => storage} />);
    fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
    fireEvent.change(screen.getByLabelText('Reduced motion'), { target: { value: 'reduce' } });
    expect(document.documentElement.getAttribute('data-motion')).toBe('reduce');
    const reset = screen.getByRole('button', { name: 'Reset display preferences' });
    reset.focus();
    fireEvent.click(reset);
    expect(document.documentElement.getAttribute('data-theme')).toBe('system');
    expect(document.documentElement.getAttribute('data-motion')).toBe('system');
    expect(screen.getByLabelText<HTMLSelectElement>('Reduced motion').value).toBe('system');
    expect(records.has(DISPLAY_PREFERENCES_KEY)).toBe(false);
    expect(records.get('unrelated')).toBe(privateMarker);
    expect(document.activeElement).toBe(reset);
  });

  it('restores saved selections across remounts without writing during restoration', () => {
    const { storage } = memoryStorage({ [DISPLAY_PREFERENCES_KEY]: '{"version":1,"theme":"dark","motion":"reduce"}' });
    const first = render(<DisplayPreferences storage={() => storage} />);
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(document.documentElement.getAttribute('data-motion')).toBe('reduce');
    first.unmount();
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(document.documentElement.hasAttribute('data-motion')).toBe(false);
    render(<DisplayPreferences storage={() => storage} />);
    fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
    expect(screen.getByLabelText<HTMLSelectElement>('Theme').value).toBe('dark');
    expect(screen.getByLabelText<HTMLSelectElement>('Reduced motion').value).toBe('reduce');
    expect(storage.setItem).not.toHaveBeenCalled();
  });

  it('applies a tab-only choice when storage fails and withholds exception details', () => {
    render(<DisplayPreferences storage={() => { throw new Error(privateMarker); }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
    fireEvent.change(screen.getByLabelText('Theme'), { target: { value: 'dark' } });
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(screen.getByRole('status').textContent).toBe('Changes apply to this tab, but could not be saved in this browser.');
    expect(document.body.textContent).not.toContain(privateMarker);
  });

  it('returns focus on Escape and restores the prior root attributes when unmounted', () => {
    document.documentElement.setAttribute('data-theme', 'light');
    document.documentElement.setAttribute('data-motion', 'reduce');
    const { storage } = memoryStorage();
    const view = render(<DisplayPreferences storage={() => storage} />);
    const trigger = screen.getByRole('button', { name: 'Display preferences' });
    fireEvent.click(trigger);
    const theme = screen.getByLabelText('Theme');
    theme.focus();
    fireEvent.keyDown(theme, { key: 'Escape' });
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(document.getElementById(trigger.getAttribute('aria-controls')!)?.hidden).toBe(true);
    expect(document.activeElement).toBe(trigger);
    view.unmount();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(document.documentElement.getAttribute('data-motion')).toBe('reduce');
  });

  it('retains the shell preference across a real route transition without another write or request', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
    fireEvent.change(screen.getByLabelText('Theme'), { target: { value: 'dark' } });
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(screen.getByLabelText<HTMLSelectElement>('Theme').value).toBe('dark');
    expect(writes).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });
});
