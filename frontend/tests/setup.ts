import { cleanup } from '@testing-library/preact';
import { afterEach, beforeEach, vi } from 'vitest';

beforeEach(() => {
  if (typeof window !== 'undefined') window.history.replaceState(null, '', '/');
});

afterEach(() => {
  if (typeof window !== 'undefined') cleanup();
  vi.unstubAllGlobals();
});
