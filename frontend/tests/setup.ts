import { cleanup } from '@testing-library/preact';
import { afterEach, beforeEach, vi } from 'vitest';
import { registerContractExtension } from '../src/api/decode';
import { lazyContractSchema } from '../src/api/generated-schema-lazy';

// Lazy routes register this extension at load; tests decode every fixture directly.
registerContractExtension(lazyContractSchema);

beforeEach(() => {
  if (typeof window !== 'undefined') window.history.replaceState(null, '', '/');
});

afterEach(() => {
  if (typeof window !== 'undefined') cleanup();
  vi.unstubAllGlobals();
});
