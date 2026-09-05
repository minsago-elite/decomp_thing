import { describe, expect, it } from 'vitest';
import { appPath, normalizeBasePath } from '../src/app/paths';

describe('deployment prefix', () => {
  it('normalizes root and nested base paths without changing route identity', () => {
    expect(normalizeBasePath('/')).toBe('');
    expect(normalizeBasePath('')).toBe('');
    expect(normalizeBasePath('/tools/decomp/')).toBe('/tools/decomp');
    expect(appPath(normalizeBasePath('/tools/decomp/'), '/runtime')).toBe('/tools/decomp/runtime');
  });

  it.each(['//other.example', 'https://other.example', '/../outside', '/foo?secret', '/foo#fragment', '/%2fhidden', '/foo//bar'])(
    'rejects a noncanonical prefix %s', (value) => {
      expect(() => normalizeBasePath(value)).toThrow('base path is invalid');
    },
  );
});
