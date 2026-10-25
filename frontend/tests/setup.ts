import { cleanup, configure } from '@testing-library/preact';
import { afterEach, beforeEach, vi } from 'vitest';

// Every route is a lazy chunk; a first transform under a loaded host can exceed the 1 s default.
configure({ asyncUtilTimeout: 5000 });

beforeEach(() => {
  if (typeof window !== 'undefined') window.history.replaceState(null, '', '/');
});

afterEach(() => {
  if (typeof window !== 'undefined') cleanup();
  vi.unstubAllGlobals();
});
