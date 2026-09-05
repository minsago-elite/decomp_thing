import { cleanup } from '@testing-library/preact';
import { afterEach, beforeEach, vi } from 'vitest';

beforeEach(() => {
  window.history.replaceState(null, '', '/');
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
