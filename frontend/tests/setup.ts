import { cleanup, configure } from '@testing-library/preact';
import { options } from 'preact';
import { afterEach, beforeEach, vi } from 'vitest';

// Preact's default after-paint fallback uses Node timers, which can outlive
// JSDOM teardown and then access deleted browser globals. Keep both the frame
// and its 100 ms fallback owned by this window so close() cancels pending work.
if (typeof window !== 'undefined') {
  // Vitest aliases `window` to the Node global; use its actual JSDOM realm.
  const browser = (globalThis as typeof globalThis & { jsdom: { window: Window } }).jsdom.window;
  options.requestAnimationFrame = callback => {
    const done = () => {
      browser.clearTimeout(timeout);
      browser.cancelAnimationFrame(frame);
      browser.setTimeout(callback);
    };
    const timeout = browser.setTimeout(done, 100);
    const frame = browser.requestAnimationFrame(done);
  };
}

// Every route is a lazy chunk; a first transform under a loaded host can exceed the 1 s default.
configure({ asyncUtilTimeout: 5000 });

beforeEach(() => {
  if (typeof window !== 'undefined') window.history.replaceState(null, '', '/');
});

afterEach(() => {
  if (typeof window !== 'undefined') cleanup();
  vi.unstubAllGlobals();
});
