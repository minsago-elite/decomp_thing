import { displayPreferencesCopy as copy } from '../copy/shell';
import { useLayoutEffect, useRef, useState } from 'preact/hooks';

export type DisplayPreferenceValues = Readonly<{
  theme: 'system' | 'light' | 'dark';
  motion: 'system' | 'reduce';
}>;
type PreferenceStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
type StorageAccess = () => PreferenceStorage;

export const DISPLAY_PREFERENCES_KEY = 'decomp.display-preferences.v1';
const defaults: DisplayPreferenceValues = Object.freeze({ theme: 'system', motion: 'system' });
const browserStorage: StorageAccess = () => window.localStorage;

function validValues(value: Record<string, unknown>): value is Record<string, unknown> & DisplayPreferenceValues {
  return (value.theme === 'system' || value.theme === 'light' || value.theme === 'dark')
    && (value.motion === 'system' || value.motion === 'reduce');
}

/** Read one bounded display-only record. Invalid data is neither displayed nor rewritten on startup. */
export function readDisplayPreferences(storage: StorageAccess = browserStorage): DisplayPreferenceValues {
  try {
    const raw = storage().getItem(DISPLAY_PREFERENCES_KEY);
    if (raw === null || raw.length > 256) return defaults;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return defaults;
    const record = value as Record<string, unknown>;
    if (Object.keys(record).sort().join(',') !== 'motion,theme,version' || record.version !== 1 || !validValues(record)) return defaults;
    return { theme: record.theme, motion: record.motion };
  } catch { return defaults; }
}

/** Select the two admitted enums explicitly; other caller data can never enter storage. */
export function writeDisplayPreferences(values: DisplayPreferenceValues, storage: StorageAccess = browserStorage): boolean {
  try {
    const selected = { theme: values.theme, motion: values.motion };
    if (!validValues(selected)) return false;
    const encoded = JSON.stringify({ version: 1, theme: selected.theme, motion: selected.motion });
    const target = storage();
    target.setItem(DISPLAY_PREFERENCES_KEY, encoded);
    return target.getItem(DISPLAY_PREFERENCES_KEY) === encoded;
  } catch { return false; }
}

export function resetDisplayPreferences(storage: StorageAccess = browserStorage): boolean {
  try {
    const target = storage();
    target.removeItem(DISPLAY_PREFERENCES_KEY);
    return target.getItem(DISPLAY_PREFERENCES_KEY) === null;
  } catch { return false; }
}

export function DisplayPreferences({ storage = browserStorage }: { storage?: StorageAccess }) {
  const [values, setValues] = useState(() => readDisplayPreferences(storage));
  const [open, setOpen] = useState(false);
  const [saved, setSaved] = useState<'idle' | 'saved' | 'memory'>('idle');
  const trigger = useRef<HTMLButtonElement>(null);

  useLayoutEffect(() => {
    const root = document.documentElement;
    const previousTheme = root.getAttribute('data-theme');
    const previousMotion = root.getAttribute('data-motion');
    root.setAttribute('data-theme', values.theme);
    root.setAttribute('data-motion', values.motion);
    return () => {
      if (previousTheme === null) root.removeAttribute('data-theme');
      else root.setAttribute('data-theme', previousTheme);
      if (previousMotion === null) root.removeAttribute('data-motion');
      else root.setAttribute('data-motion', previousMotion);
    };
  }, [values.theme, values.motion]);

  function update(theme: string, motion: string) {
    const next = { theme, motion };
    if (!validValues(next)) return;
    setValues(next);
    setSaved(writeDisplayPreferences(next, storage) ? 'saved' : 'memory');
  }

  return <div class={`display-preferences${open ? ' is-open' : ''}`} onKeyDown={event => {
    if (open && event.key === 'Escape') {
      event.preventDefault();
      setOpen(false);
      trigger.current?.focus();
    }
  }}>
    <button type="button" ref={trigger} aria-expanded={open} aria-controls="display-preferences-panel"
      onClick={() => setOpen(current => !current)}>{copy.displayPreferences}</button>
    <div id="display-preferences-panel" class="display-preferences-panel" hidden={!open}>
      <div class="display-preference-fields">
        <label>{copy.theme}<select value={values.theme} onChange={event => update(event.currentTarget.value, values.motion)}>
            <option value="system">{copy.system}</option>
            <option value="light">{copy.light}</option>
            <option value="dark">{copy.dark}</option>
          </select>
        </label>
        <label>{copy.reducedMotion}<select value={values.motion} onChange={event => update(values.theme, event.currentTarget.value)}>
            <option value="system">{copy.system}</option>
            <option value="reduce">{copy.alwaysReduce}</option>
          </select>
        </label>
      </div>
      <p>{copy.systemFollowsYourDeviceSettingsChangesAreSavedInThis}</p>
      <button type="button" onClick={() => {
        setValues(defaults);
        setSaved(resetDisplayPreferences(storage) ? 'saved' : 'memory');
      }}>{copy.resetDisplayPreferences}</button>
      <p role="status">{saved === 'saved' ? copy.displayPreferencesSavedInThisBrowser
        : saved === 'memory' ? copy.changesApplyToThisTabButCouldNotBeSaved : ''}</p>
    </div>
  </div>;
}
