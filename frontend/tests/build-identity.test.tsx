import { render, screen } from '@testing-library/preact';
import { describe, expect, it, vi } from 'vitest';
import { readBuildIdentity } from '../src/app/buildIdentity';
import Runtime from '../src/routes/Runtime';

function shellMetadata(entries: [string, string][]): Document {
  const shell = document.implementation.createHTMLDocument('Build identity');
  for (const [name, content] of entries) {
    const meta = shell.createElement('meta');
    meta.name = name;
    meta.content = content;
    shell.head.append(meta);
  }
  return shell;
}

describe('packaged shell build identity', () => {
  it('shows the exact non-secret identities from the server shell without probing capabilities', () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const buildId = '0123456789abcdef'.repeat(4);
    const identity = readBuildIdentity(shellMetadata([
      ['decomp-ui-build', buildId],
      ['decomp-application-version', '0.1.0+build.2'],
    ]));
    render(<Runtime identity={identity} />);
    expect(screen.getByText(buildId)).toBeTruthy();
    expect(screen.getByText('0.1.0+build.2')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Runtime information is not connected' })).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('keeps missing or malformed identity explicitly unavailable', () => {
    expect(readBuildIdentity(shellMetadata([]))).toEqual({ uiBuildId: null, applicationVersion: null });
    const identity = readBuildIdentity(shellMetadata([
      ['decomp-ui-build', 'not-a-content-identity'],
      ['decomp-application-version', '/private/host/path'],
    ]));
    render(<Runtime identity={identity} />);
    expect(screen.getAllByText('Unavailable')).toHaveLength(2);
    expect(screen.queryByText('/private/host/path')).toBeNull();
  });

  it.each(['', '.1', '_1', '1_2', '+1', '-1', '1\n', ' 1'])(
    'matches the server version grammar for %s', (version) => {
      expect(readBuildIdentity(shellMetadata([
        ['decomp-application-version', version],
      ])).applicationVersion).toBeNull();
    },
  );

  it('accepts the server maximum version length and rejects noncanonical hashes', () => {
    const version = 'v' + '1'.repeat(63);
    expect(readBuildIdentity(shellMetadata([
      ['decomp-application-version', version],
      ['decomp-ui-build', 'a'.repeat(64) + '\n'],
    ]))).toEqual({ applicationVersion: version, uiBuildId: null });
  });

  it('rejects ambiguous duplicate meta values and overlong versions', () => {
    expect(readBuildIdentity(shellMetadata([
      ['decomp-ui-build', 'a'.repeat(64)],
      ['decomp-ui-build', 'b'.repeat(64)],
      ['decomp-application-version', '1'.repeat(65)],
    ]))).toEqual({ uiBuildId: null, applicationVersion: null });
  });
});
